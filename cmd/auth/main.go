package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/gumpalan/svc-auth/internal/database"
	"github.com/gumpalan/svc-auth/internal/device"
	"github.com/gumpalan/svc-auth/internal/httpapi"
	"github.com/gumpalan/svc-auth/internal/store"
	"github.com/gumpalan/svc-auth/internal/token"
	"github.com/gumpalan/svc-auth/migrations"
)

func main() {
	cfg, err := database.LoadConfig("auth")
	if err != nil {
		log.Fatalf("Gagal memuat konfigurasi database: %v", err)
	}

	db, dialect, err := database.Open(cfg)
	if err != nil {
		log.Fatalf("Gagal membuka database: %v", err)
	}
	defer db.Close()

	if cfg.AutoMigrate {
		if err := database.Migrate(db, dialect, migrations.FS, ".", "auth_migrations"); err != nil {
			log.Fatalf("Migrasi gagal: %v", err)
		}
	}

	st := store.New(db, dialect)

	args := os.Args[1:]
	if len(args) > 0 && args[0] == "device" {
		handleDeviceCLI(st, args[1:])
		return
	}

	// Default: jalankan server HTTP
	handler := httpapi.NewHandler(st)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8001"
	}

	addr := fmt.Sprintf("127.0.0.1:%s", port)
	log.Printf("Server svc-auth berjalan di http://%s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server berhenti dengan galat: %v", err)
	}
}

func handleDeviceCLI(st *store.Store, args []string) {
	ctx := context.Background()
	if len(args) == 0 || args[0] == "list" {
		listDevices(ctx, st)
		return
	}

	switch args[0] {
	case "approve":
		if len(args) < 2 {
			fmt.Println("Penggunaan: auth device approve <device_id>")
			os.Exit(1)
		}
		approveDevice(ctx, st, args[1])

	case "revoke":
		if len(args) < 2 {
			fmt.Println("Penggunaan: auth device revoke <device_id>")
			os.Exit(1)
		}
		revokeDevice(ctx, st, args[1])

	default:
		fmt.Printf("Perintah tidak dikenal: %s\n", args[0])
		fmt.Println("Perintah tersedia: list, approve <id>, revoke <id>")
		os.Exit(1)
	}
}

func listDevices(ctx context.Context, st *store.Store) {
	devices, err := st.ListDevices(ctx)
	if err != nil {
		log.Fatalf("Gagal mengambil daftar perangkat: %v", err)
	}

	if len(devices) == 0 {
		fmt.Println("Belum ada perangkat terdaftar.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "DEVICE ID\tNAMA\tSTATUS\tTERDAFTAR\tDISETUJUI")
	for _, d := range devices {
		created := time.Unix(d.CreatedAt, 0).Format("2006-01-02 15:04:05")
		approved := "-"
		if d.ApprovedAt != nil {
			approved = time.Unix(*d.ApprovedAt, 0).Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", d.ID, d.Name, d.Status, created, approved)
	}
	_ = w.Flush()
}

func approveDevice(ctx context.Context, st *store.Store, deviceID string) {
	dev, err := st.GetDevice(ctx, deviceID)
	if err != nil {
		log.Fatalf("Perangkat %s tidak ditemukan: %v", deviceID, err)
	}

	now := time.Now().Unix()
	if err := st.UpdateDeviceStatus(ctx, deviceID, device.StatusApproved, &now); err != nil {
		log.Fatalf("Gagal menyetujui perangkat: %v", err)
	}

	tokStr, err := token.Generate()
	if err != nil {
		log.Fatalf("Gagal membuat token: %v", err)
	}

	tok := &token.Token{
		Token:     tokStr,
		DeviceID:  deviceID,
		CreatedAt: now,
	}
	if err := st.CreateToken(ctx, tok); err != nil {
		log.Fatalf("Gagal menyimpan token: %v", err)
	}

	fmt.Printf("[OK] Perangkat '%s' (%s) berhasil DISETUJUI.\n", dev.Name, dev.ID)
	fmt.Printf("Token akses baru dibuat: %s\n", tokStr)
}

func revokeDevice(ctx context.Context, st *store.Store, deviceID string) {
	dev, err := st.GetDevice(ctx, deviceID)
	if err != nil {
		log.Fatalf("Perangkat %s tidak ditemukan: %v", deviceID, err)
	}

	if err := st.UpdateDeviceStatus(ctx, deviceID, device.StatusRevoked, nil); err != nil {
		log.Fatalf("Gagal mencabut perangkat: %v", err)
	}

	if err := st.RevokeTokensByDeviceID(ctx, deviceID); err != nil {
		log.Fatalf("Gagal menghapus token perangkat: %v", err)
	}

	fmt.Printf("[OK] Perangkat '%s' (%s) berhasil DICABUT (REVOKED). Seluruh token telah dihapus.\n", dev.Name, dev.ID)
}
