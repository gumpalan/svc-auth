package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gumpalan/svc-auth/internal/device"
	"github.com/gumpalan/svc-auth/internal/store"
	"github.com/gumpalan/svc-auth/internal/token"
	"github.com/gumpalan/svc-auth/internal/user"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	store *store.Store
}

func NewHandler(s *store.Store) http.Handler {
	h := &Handler{store: s}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /auth/v1/register", h.handleRegister)
	mux.HandleFunc("POST /auth/v1/login", h.handleLogin)
	mux.HandleFunc("GET /auth/v1/register/{deviceId}/status", h.handleRegisterStatus)
	mux.HandleFunc("GET /auth/v1/verify", h.handleVerify)
	mux.HandleFunc("GET /auth/v1/modules", h.handleModules)
	mux.HandleFunc("GET /healthz", h.handleHealthz)

	// User self-service endpoints (butuh bearer token perangkat aktif)
	mux.HandleFunc("GET /auth/v1/user/profile", h.handleUserProfile)
	mux.HandleFunc("PUT /auth/v1/user/profile", h.handleUpdateUserProfile)
	mux.HandleFunc("PUT /auth/v1/user/password", h.handleUpdateUserPassword)
	mux.HandleFunc("GET /auth/v1/user/devices", h.handleListUserDevices)
	mux.HandleFunc("DELETE /auth/v1/user/devices/{deviceId}", h.handleRevokeUserDevice)

	return mux
}

type registerRequest struct {
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
}

type registerResponse struct {
	DeviceID string `json:"deviceId"`
	UserID   string `json:"userId,omitempty"`
	Status   string `json:"status"`
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	var assignedUserID *string

	// Jika pendaftaran menyertakan akun user
	if req.Username != "" && req.Password != "" {
		// Cek apakah username sudah dipakai
		existingUser, err := h.store.GetUserByUsername(ctx, req.Username)
		if err == nil && existingUser != nil {
			http.Error(w, `{"error":"username already exists"}`, http.StatusConflict)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, `{"error":"failed to process password"}`, http.StatusInternalServerError)
			return
		}

		// Cari role: jika ini user pertama, beri admin; lainnya user biasa
		users, _ := h.store.ListUsers(ctx)
		roleName := "user"
		if len(users) == 0 {
			roleName = "admin"
		}
		role, err := h.store.GetRoleByName(ctx, roleName)
		roleID := "role_user"
		if err == nil && role != nil {
			roleID = role.ID
		}

		bUser := make([]byte, 8)
		_, _ = rand.Read(bUser)
		uID := "usr_" + hex.EncodeToString(bUser)
		now := time.Now().Unix()

		disp := req.DisplayName
		if disp == "" {
			disp = req.Username
		}

		newUser := &user.User{
			ID:           uID,
			Username:     req.Username,
			PasswordHash: string(hash),
			RoleID:       roleID,
			DisplayName:  disp,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		if err := h.store.CreateUser(ctx, newUser); err != nil {
			http.Error(w, `{"error":"failed to create user"}`, http.StatusInternalServerError)
			return
		}
		assignedUserID = &uID
	}

	// Idempotensi registrasi perangkat: jika fingerprint sudah ada
	if req.Fingerprint != "" {
		existing, err := h.store.GetDeviceByFingerprint(ctx, req.Fingerprint)
		if err == nil && existing != nil {
			if assignedUserID != nil {
				_ = h.store.UpdateDeviceUserID(ctx, existing.ID, *assignedUserID)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			uIDStr := ""
			if assignedUserID != nil {
				uIDStr = *assignedUserID
			} else if existing.UserID != nil {
				uIDStr = *existing.UserID
			}
			_ = json.NewEncoder(w).Encode(registerResponse{
				DeviceID: existing.ID,
				UserID:   uIDStr,
				Status:   string(existing.Status),
			})
			return
		}
	}

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	devID := "dev_" + hex.EncodeToString(b)

	dev := &device.Device{
		ID:          devID,
		Name:        req.Name,
		Fingerprint: req.Fingerprint,
		PublicKey:   req.PublicKey,
		Status:      device.StatusPending,
		CreatedAt:   time.Now().Unix(),
		UserID:      assignedUserID,
	}

	if err := h.store.CreateDevice(ctx, dev); err != nil {
		http.Error(w, `{"error":"failed to register device"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	uIDStr := ""
	if assignedUserID != nil {
		uIDStr = *assignedUserID
	}
	_ = json.NewEncoder(w).Encode(registerResponse{
		DeviceID: devID,
		UserID:   uIDStr,
		Status:   string(device.StatusPending),
	})
}

type loginRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey,omitempty"`
}

type loginResponse struct {
	DeviceID string     `json:"deviceId"`
	Status   string     `json:"status"`
	Token    *string    `json:"token,omitempty"`
	User     *user.User `json:"user"`
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		http.Error(w, `{"error":"username and password required"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	u, err := h.store.GetUserByUsername(ctx, req.Username)
	if err != nil {
		http.Error(w, `{"error":"invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, `{"error":"invalid username or password"}`, http.StatusUnauthorized)
		return
	}

	// Cari perangkat berdasarkan fingerprint
	var currentDev *device.Device
	if req.Fingerprint != "" {
		existing, err := h.store.GetDeviceByFingerprint(ctx, req.Fingerprint)
		if err == nil && existing != nil {
			currentDev = existing
			// Tautkan ke user jika belum atau jika user berganti
			_ = h.store.UpdateDeviceUserID(ctx, existing.ID, u.ID)
		}
	}

	// Jika perangkat belum ada, daftarkan otomatis dengan status pending
	if currentDev == nil {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		devID := "dev_" + hex.EncodeToString(b)
		devName := req.Name
		if devName == "" {
			devName = "Unknown Device"
		}
		newDev := &device.Device{
			ID:          devID,
			Name:        devName,
			Fingerprint: req.Fingerprint,
			PublicKey:   req.PublicKey,
			Status:      device.StatusPending,
			CreatedAt:   time.Now().Unix(),
			UserID:      &u.ID,
		}
		if err := h.store.CreateDevice(ctx, newDev); err != nil {
			http.Error(w, `{"error":"failed to register device for user"}`, http.StatusInternalServerError)
			return
		}
		currentDev = newDev
	}

	var tokStr *string
	if currentDev.Status == device.StatusApproved {
		tok, err := h.store.GetTokenByDeviceID(ctx, currentDev.ID)
		if err == nil && tok != nil {
			tokStr = &tok.Token
		} else {
			// Buat token baru jika disetujui tapi belum punya token
			tVal, err := token.Generate()
			if err == nil {
				now := time.Now().Unix()
				_ = h.store.CreateToken(ctx, &token.Token{
					Token:     tVal,
					DeviceID:  currentDev.ID,
					CreatedAt: now,
				})
				tokStr = &tVal
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(loginResponse{
		DeviceID: currentDev.ID,
		Status:   string(currentDev.Status),
		Token:    tokStr,
		User:     u,
	})
}

type deviceStatusResponse struct {
	DeviceID  string     `json:"deviceId"`
	Name      string     `json:"name"`
	Status    string     `json:"status"`
	CreatedAt int64      `json:"createdAt"`
	Token     *string    `json:"token"`
	User      *user.User `json:"user,omitempty"`
}

func (h *Handler) handleRegisterStatus(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("deviceId")
	if deviceID == "" {
		http.Error(w, `{"error":"missing deviceId"}`, http.StatusBadRequest)
		return
	}

	dev, err := h.store.GetDevice(r.Context(), deviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	var tokStr *string
	if dev.Status == device.StatusApproved {
		tok, err := h.store.GetTokenByDeviceID(r.Context(), deviceID)
		if err == nil && tok != nil {
			tokStr = &tok.Token
		}
	}

	var linkedUser *user.User
	if dev.UserID != nil && *dev.UserID != "" {
		linkedUser, _ = h.store.GetUserByID(r.Context(), *dev.UserID)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(deviceStatusResponse{
		DeviceID:  dev.ID,
		Name:      dev.Name,
		Status:    string(dev.Status),
		CreatedAt: dev.CreatedAt,
		Token:     tokStr,
		User:      linkedUser,
	})
}

func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	tokStr := extractBearerToken(r)
	if tokStr == "" {
		http.Error(w, `{"error":"missing or invalid authorization header"}`, http.StatusUnauthorized)
		return
	}

	u, dev, err := h.store.GetUserByToken(r.Context(), tokStr)
	if err != nil || dev == nil || dev.Status != device.StatusApproved {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("X-Device-Id", dev.ID)
	if u != nil {
		w.Header().Set("X-User-Id", u.ID)
		if u.Role != nil {
			w.Header().Set("X-User-Role", u.Role.Name)
			w.Header().Set("X-Allowed-Modules", strings.Join(u.Role.AllowedModules, ","))
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleModules(w http.ResponseWriter, r *http.Request) {
	tokStr := extractBearerToken(r)
	if tokStr == "" {
		http.Error(w, `{"error":"missing or invalid authorization header"}`, http.StatusUnauthorized)
		return
	}

	u, dev, err := h.store.GetUserByToken(r.Context(), tokStr)
	if err != nil || dev == nil || dev.Status != device.StatusApproved {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	modules := []string{"iot"}
	if u != nil && u.Role != nil && len(u.Role.AllowedModules) > 0 {
		modules = u.Role.AllowedModules
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"modules": modules,
	})
}

func (h *Handler) handleUserProfile(w http.ResponseWriter, r *http.Request) {
	tokStr := extractBearerToken(r)
	if tokStr == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	u, _, err := h.store.GetUserByToken(r.Context(), tokStr)
	if err != nil || u == nil {
		http.Error(w, `{"error":"user not found or unauthorized"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(u)
}

type updateProfileRequest struct {
	DisplayName string `json:"displayName"`
}

func (h *Handler) handleUpdateUserProfile(w http.ResponseWriter, r *http.Request) {
	tokStr := extractBearerToken(r)
	if tokStr == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	u, _, err := h.store.GetUserByToken(r.Context(), tokStr)
	if err != nil || u == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req updateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DisplayName == "" {
		http.Error(w, `{"error":"invalid payload"}`, http.StatusBadRequest)
		return
	}

	if err := h.store.UpdateUserProfile(r.Context(), u.ID, req.DisplayName); err != nil {
		http.Error(w, `{"error":"failed to update profile"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

type updatePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

func (h *Handler) handleUpdateUserPassword(w http.ResponseWriter, r *http.Request) {
	tokStr := extractBearerToken(r)
	if tokStr == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	u, _, err := h.store.GetUserByToken(r.Context(), tokStr)
	if err != nil || u == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req updatePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.OldPassword == "" || req.NewPassword == "" {
		http.Error(w, `{"error":"oldPassword and newPassword required"}`, http.StatusBadRequest)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.OldPassword)); err != nil {
		http.Error(w, `{"error":"incorrect old password"}`, http.StatusUnauthorized)
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error":"failed to hash new password"}`, http.StatusInternalServerError)
		return
	}

	if err := h.store.UpdateUserPassword(r.Context(), u.ID, string(newHash)); err != nil {
		http.Error(w, `{"error":"failed to update password"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (h *Handler) handleListUserDevices(w http.ResponseWriter, r *http.Request) {
	tokStr := extractBearerToken(r)
	if tokStr == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	u, _, err := h.store.GetUserByToken(r.Context(), tokStr)
	if err != nil || u == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	devices, err := h.store.ListDevicesByUserID(r.Context(), u.ID)
	if err != nil {
		http.Error(w, `{"error":"failed to list devices"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(devices)
}

func (h *Handler) handleRevokeUserDevice(w http.ResponseWriter, r *http.Request) {
	tokStr := extractBearerToken(r)
	if tokStr == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	u, _, err := h.store.GetUserByToken(r.Context(), tokStr)
	if err != nil || u == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	deviceID := r.PathValue("deviceId")
	if deviceID == "" {
		http.Error(w, `{"error":"missing deviceId"}`, http.StatusBadRequest)
		return
	}

	if err := h.store.RevokeDeviceByUser(r.Context(), deviceID, u.ID); err != nil {
		http.Error(w, `{"error":"failed to revoke device"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (h *Handler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","service":"svc-auth"}`))
}

func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
