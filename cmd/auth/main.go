package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gumpalan/svc-auth/internal/database"
	"github.com/gumpalan/svc-auth/internal/device"
	"github.com/gumpalan/svc-auth/internal/httpapi"
	"github.com/gumpalan/svc-auth/internal/store"
	"github.com/gumpalan/svc-auth/internal/token"
	"github.com/gumpalan/svc-auth/internal/user"
	"github.com/gumpalan/svc-auth/migrations"
	"golang.org/x/crypto/bcrypt"
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
	if len(args) > 0 {
		switch args[0] {
		case "device":
			handleDeviceCLI(st, args[1:])
			return
		case "user":
			handleUserCLI(st, args[1:])
			return
		case "role":
			handleRoleCLI(st, args[1:])
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}

	// Default: jalankan server HTTP
	handler := httpapi.NewHandler(st)

	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8001"
	}

	addr := fmt.Sprintf("%s:%s", host, port)
	log.Printf("Server svc-auth berjalan di http://%s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server berhenti dengan galat: %v", err)
	}
}

func printUsage() {
	fmt.Println("Gumpalan Auth CLI")
	fmt.Println("\nPenggunaan:")
	fmt.Println("  auth device list")
	fmt.Println("  auth device approve <device_id>")
	fmt.Println("  auth device revoke <device_id>")
	fmt.Println("  auth user list")
	fmt.Println("  auth user create <username> <password> [role] [display_name]")
	fmt.Println("  auth user reset-password <username> <new_password>")
	fmt.Println("  auth role list")
	fmt.Println("  auth role create <name> <modules_comma_separated> [description]")
}

// ------------------- Device CLI -------------------

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
	fmt.Fprintln(w, "DEVICE ID\tNAMA\tUSER\tSTATUS\tTERDAFTAR\tDISETUJUI")
	for _, d := range devices {
		created := time.Unix(d.CreatedAt, 0).Format("2006-01-02 15:04:05")
		approved := "-"
		if d.ApprovedAt != nil {
			approved = time.Unix(*d.ApprovedAt, 0).Format("2006-01-02 15:04:05")
		}
		uName := "-"
		if d.UserID != nil && *d.UserID != "" {
			u, err := st.GetUserByID(ctx, *d.UserID)
			if err == nil && u != nil {
				uName = u.Username
			} else {
				uName = *d.UserID
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", d.ID, d.Name, uName, d.Status, created, approved)
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

// ------------------- User CLI -------------------

func handleUserCLI(st *store.Store, args []string) {
	ctx := context.Background()
	if len(args) == 0 || args[0] == "list" {
		listUsers(ctx, st)
		return
	}

	switch args[0] {
	case "create":
		if len(args) < 3 {
			fmt.Println("Penggunaan: auth user create <username> <password> [role] [display_name]")
			os.Exit(1)
		}
		roleName := "user"
		if len(args) >= 4 && args[3] != "" {
			roleName = args[3]
		}
		displayName := args[1]
		if len(args) >= 5 && args[4] != "" {
			displayName = args[4]
		}
		createUser(ctx, st, args[1], args[2], roleName, displayName)

	case "reset-password":
		if len(args) < 3 {
			fmt.Println("Penggunaan: auth user reset-password <username> <new_password>")
			os.Exit(1)
		}
		resetUserPassword(ctx, st, args[1], args[2])

	default:
		fmt.Printf("Perintah user tidak dikenal: %s\n", args[0])
		fmt.Println("Perintah tersedia: list, create <user> <pass> [role], reset-password <user> <new_pass>")
		os.Exit(1)
	}
}

func listUsers(ctx context.Context, st *store.Store) {
	users, err := st.ListUsers(ctx)
	if err != nil {
		log.Fatalf("Gagal mengambil daftar pengguna: %v", err)
	}

	if len(users) == 0 {
		fmt.Println("Belum ada pengguna terdaftar.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "USER ID\tUSERNAME\tDISPLAY NAME\tROLE\tMODULES\tDIBUAT")
	for _, u := range users {
		created := time.Unix(u.CreatedAt, 0).Format("2006-01-02 15:04:05")
		roleName := "-"
		mods := "-"
		if u.Role != nil {
			roleName = u.Role.Name
			mods = strings.Join(u.Role.AllowedModules, ",")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", u.ID, u.Username, u.DisplayName, roleName, mods, created)
	}
	_ = w.Flush()
}

func createUser(ctx context.Context, st *store.Store, username, password, roleName, displayName string) {
	existing, _ := st.GetUserByUsername(ctx, username)
	if existing != nil {
		log.Fatalf("Username '%s' sudah terdaftar.", username)
	}

	role, err := st.GetRoleByName(ctx, roleName)
	if err != nil {
		log.Fatalf("Role '%s' tidak ditemukan: %v", roleName, err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Gagal memproses password: %v", err)
	}

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	uID := "usr_" + hex.EncodeToString(b)
	now := time.Now().Unix()

	u := &user.User{
		ID:           uID,
		Username:     username,
		PasswordHash: string(hash),
		RoleID:       role.ID,
		DisplayName:  displayName,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := st.CreateUser(ctx, u); err != nil {
		log.Fatalf("Gagal membuat user: %v", err)
	}

	fmt.Printf("[OK] Pengguna '%s' (%s) berhasil dibuat dengan peran '%s'.\n", username, uID, role.Name)
}

func resetUserPassword(ctx context.Context, st *store.Store, username, newPassword string) {
	u, err := st.GetUserByUsername(ctx, username)
	if err != nil {
		log.Fatalf("Pengguna '%s' tidak ditemukan: %v", username, err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Gagal memproses password baru: %v", err)
	}

	if err := st.UpdateUserPassword(ctx, u.ID, string(hash)); err != nil {
		log.Fatalf("Gagal memperbarui password: %v", err)
	}

	fmt.Printf("[OK] Password pengguna '%s' berhasil diperbarui.\n", username)
}

// ------------------- Role CLI -------------------

func handleRoleCLI(st *store.Store, args []string) {
	ctx := context.Background()
	if len(args) == 0 || args[0] == "list" {
		listRoles(ctx, st)
		return
	}

	switch args[0] {
	case "create":
		if len(args) < 3 {
			fmt.Println("Penggunaan: auth role create <name> <modules_comma_separated> [description]")
			os.Exit(1)
		}
		desc := ""
		if len(args) >= 4 {
			desc = args[3]
		}
		createRole(ctx, st, args[1], args[2], desc)

	default:
		fmt.Printf("Perintah role tidak dikenal: %s\n", args[0])
		fmt.Println("Perintah tersedia: list, create <name> <modules> [description]")
		os.Exit(1)
	}
}

func listRoles(ctx context.Context, st *store.Store) {
	roles, err := st.ListRoles(ctx)
	if err != nil {
		log.Fatalf("Gagal mengambil daftar peran: %v", err)
	}

	if len(roles) == 0 {
		fmt.Println("Belum ada peran terdaftar.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ROLE ID\tNAMA\tMODUL DIIZINKAN\tDESKRIPSI")
	for _, r := range roles {
		mods := strings.Join(r.AllowedModules, ",")
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.ID, r.Name, mods, r.Description)
	}
	_ = w.Flush()
}

func createRole(ctx context.Context, st *store.Store, name, modulesRaw, description string) {
	existing, _ := st.GetRoleByName(ctx, name)
	if existing != nil {
		log.Fatalf("Peran '%s' sudah terdaftar.", name)
	}

	var mods []string
	if strings.HasPrefix(strings.TrimSpace(modulesRaw), "[") {
		_ = json.Unmarshal([]byte(modulesRaw), &mods)
	} else {
		for _, m := range strings.Split(modulesRaw, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				mods = append(mods, m)
			}
		}
	}

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	roleID := "role_" + hex.EncodeToString(b)

	r := &user.Role{
		ID:             roleID,
		Name:           name,
		Description:    description,
		AllowedModules: mods,
		CreatedAt:      time.Now().Unix(),
	}

	if err := st.CreateRole(ctx, r); err != nil {
		log.Fatalf("Gagal membuat peran: %v", err)
	}

	fmt.Printf("[OK] Peran '%s' (%s) berhasil dibuat. Modul: %v\n", name, roleID, mods)
}
