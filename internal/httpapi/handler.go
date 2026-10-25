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
)

type Handler struct {
	store *store.Store
}

func NewHandler(s *store.Store) http.Handler {
	h := &Handler{store: s}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /auth/v1/register", h.handleRegister)
	mux.HandleFunc("GET /auth/v1/register/{deviceId}/status", h.handleRegisterStatus)
	mux.HandleFunc("GET /auth/v1/verify", h.handleVerify)
	mux.HandleFunc("GET /auth/v1/modules", h.handleModules)
	mux.HandleFunc("GET /healthz", h.handleHealthz)

	return mux
}

type registerRequest struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
}

type registerResponse struct {
	DeviceID string `json:"deviceId"`
	Status   string `json:"status"`
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, `{"error":"invalid request payload"}`, http.StatusBadRequest)
		return
	}

	// Idempotensi registrasi: jika fingerprint perangkat telah terdaftar sebelumnya,
	// kembalikan entitas perangkat yang telah ada untuk mencegah duplikasi data.
	if req.Fingerprint != "" {
		existing, err := h.store.GetDeviceByFingerprint(r.Context(), req.Fingerprint)
		if err == nil && existing != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(registerResponse{
				DeviceID: existing.ID,
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
	}

	if err := h.store.CreateDevice(r.Context(), dev); err != nil {
		http.Error(w, `{"error":"failed to register device"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(registerResponse{
		DeviceID: devID,
		Status:   string(device.StatusPending),
	})
}

type deviceStatusResponse struct {
	DeviceID  string  `json:"deviceId"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	CreatedAt int64   `json:"createdAt"`
	Token     *string `json:"token"`
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(deviceStatusResponse{
		DeviceID:  dev.ID,
		Name:      dev.Name,
		Status:    string(dev.Status),
		CreatedAt: dev.CreatedAt,
		Token:     tokStr,
	})
}

func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	tokStr := extractBearerToken(r)
	if tokStr == "" {
		http.Error(w, `{"error":"missing or invalid authorization header"}`, http.StatusUnauthorized)
		return
	}

	dev, err := h.store.GetDeviceByToken(r.Context(), tokStr)
	if err != nil || dev.Status != device.StatusApproved {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("X-Device-Id", dev.ID)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleModules(w http.ResponseWriter, r *http.Request) {
	tokStr := extractBearerToken(r)
	if tokStr == "" {
		http.Error(w, `{"error":"missing or invalid authorization header"}`, http.StatusUnauthorized)
		return
	}

	dev, err := h.store.GetDeviceByToken(r.Context(), tokStr)
	if err != nil || dev.Status != device.StatusApproved {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"modules":["iot"]}`))
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
