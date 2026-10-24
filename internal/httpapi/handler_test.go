package httpapi_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gumpalan/svc-auth/internal/database"
	"github.com/gumpalan/svc-auth/internal/httpapi"
	"github.com/gumpalan/svc-auth/internal/store"
	"github.com/gumpalan/svc-auth/internal/token"
	"github.com/gumpalan/svc-auth/migrations"
	_ "modernc.org/sqlite"
)

func setupTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	if err := database.Migrate(db, "sqlite", migrations.FS, ".", "auth_migrations"); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}

	s := store.New(db, database.DialectSQLite)
	handler := httpapi.NewHandler(s)
	ts := httptest.NewServer(handler)
	return ts, s
}

func TestHTTP_Register_Approve_Verify_Flow(t *testing.T) {
	ts, s := setupTestServer(t)
	defer ts.Close()

	// 1. Register device
	regPayload := []byte(`{"name":"Pixel 8 Pro","publicKey":"pubkey_abc"}`)
	resp, err := http.Post(ts.URL+"/auth/v1/register", "application/json", bytes.NewReader(regPayload))
	if err != nil {
		t.Fatalf("POST /register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}

	var regRes struct {
		DeviceID string `json:"deviceId"`
		Status   string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&regRes); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if regRes.DeviceID == "" || regRes.Status != "pending" {
		t.Fatalf("unexpected reg response: %+v", regRes)
	}

	// 2. Check status (still pending)
	respStatus, err := http.Get(ts.URL + "/auth/v1/register/" + regRes.DeviceID + "/status")
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	defer respStatus.Body.Close()

	var statRes struct {
		DeviceID string  `json:"deviceId"`
		Status   string  `json:"status"`
		Token    *string `json:"token"`
	}
	if err := json.NewDecoder(respStatus.Body).Decode(&statRes); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if statRes.Status != "pending" || statRes.Token != nil {
		t.Fatalf("expected pending without token, got %+v", statRes)
	}

	// 3. Admin simulates approve via store & issue token
	ctx := t.Context()
	now := time.Now().Unix()
	if err := s.UpdateDeviceStatus(ctx, regRes.DeviceID, "approved", &now); err != nil {
		t.Fatalf("update status: %v", err)
	}
	tokStr, err := token.Generate()
	if err != nil {
		t.Fatalf("token.Generate: %v", err)
	}
	if err := s.CreateToken(ctx, &token.Token{
		Token:     tokStr,
		DeviceID:  regRes.DeviceID,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("create token: %v", err)
	}

	// 4. Check status again (approved and receives token)
	respStatus2, err := http.Get(ts.URL + "/auth/v1/register/" + regRes.DeviceID + "/status")
	if err != nil {
		t.Fatalf("GET /status 2: %v", err)
	}
	defer respStatus2.Body.Close()

	if err := json.NewDecoder(respStatus2.Body).Decode(&statRes); err != nil {
		t.Fatalf("decode status 2: %v", err)
	}
	if statRes.Status != "approved" || statRes.Token == nil || *statRes.Token != tokStr {
		t.Fatalf("expected approved with token, got %+v", statRes)
	}

	// 5. Verify token via /verify
	reqVerify, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth/v1/verify", nil)
	reqVerify.Header.Set("Authorization", "Bearer "+tokStr)
	respVerify, err := http.DefaultClient.Do(reqVerify)
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	defer respVerify.Body.Close()

	if respVerify.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", respVerify.StatusCode)
	}
	if respVerify.Header.Get("X-Device-Id") != regRes.DeviceID {
		t.Fatalf("expected X-Device-Id %s, got %s", regRes.DeviceID, respVerify.Header.Get("X-Device-Id"))
	}

	// 6. Access /modules
	reqMod, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth/v1/modules", nil)
	reqMod.Header.Set("Authorization", "Bearer "+tokStr)
	respMod, err := http.DefaultClient.Do(reqMod)
	if err != nil {
		t.Fatalf("modules request: %v", err)
	}
	defer respMod.Body.Close()

	if respMod.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /modules, got %d", respMod.StatusCode)
	}
}
