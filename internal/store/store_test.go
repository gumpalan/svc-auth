package store_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/gumpalan/svc-auth/internal/database"
	"github.com/gumpalan/svc-auth/internal/device"
	"github.com/gumpalan/svc-auth/internal/store"
	"github.com/gumpalan/svc-auth/internal/token"
	"github.com/gumpalan/svc-auth/migrations"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) (*sql.DB, *store.Store) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	if err := database.Migrate(db, "sqlite", migrations.FS, ".", "auth_migrations"); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}

	s := store.New(db, database.DialectSQLite)
	return db, s
}

func TestStore_DeviceCRUDAndToken(t *testing.T) {
	db, s := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	now := time.Now().Unix()
	dev := &device.Device{
		ID:        "dev_01",
		Name:      "Test Phone",
		PublicKey: "dummy_pubkey_content",
		Status:    device.StatusPending,
		CreatedAt: now,
	}

	if err := s.CreateDevice(ctx, dev); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	got, err := s.GetDevice(ctx, "dev_01")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if got.Name != dev.Name || got.Status != device.StatusPending {
		t.Fatalf("unexpected dev: %+v", got)
	}

	// Update to approved
	appAt := now + 10
	if err := s.UpdateDeviceStatus(ctx, "dev_01", device.StatusApproved, &appAt); err != nil {
		t.Fatalf("UpdateDeviceStatus: %v", err)
	}

	gotApp, err := s.GetDevice(ctx, "dev_01")
	if err != nil {
		t.Fatalf("GetDevice after update: %v", err)
	}
	if gotApp.Status != device.StatusApproved || gotApp.ApprovedAt == nil || *gotApp.ApprovedAt != appAt {
		t.Fatalf("unexpected approved dev: %+v", gotApp)
	}

	// Create Token
	tok := &token.Token{
		Token:     "tok_1234567890",
		DeviceID:  "dev_01",
		CreatedAt: now,
	}
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	devFromTok, err := s.GetDeviceByToken(ctx, "tok_1234567890")
	if err != nil {
		t.Fatalf("GetDeviceByToken: %v", err)
	}
	if devFromTok.ID != "dev_01" {
		t.Fatalf("expected dev_01, got %s", devFromTok.ID)
	}

	// Revoke tokens
	if err := s.RevokeTokensByDeviceID(ctx, "dev_01"); err != nil {
		t.Fatalf("RevokeTokensByDeviceID: %v", err)
	}

	_, err = s.GetDeviceByToken(ctx, "tok_1234567890")
	if err == nil {
		t.Fatal("expected error after token revocation, got nil")
	}
}
