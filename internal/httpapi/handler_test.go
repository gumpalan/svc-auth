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

func TestHTTP_UserRegister_Login_Profile_Flow(t *testing.T) {
	ts, s := setupTestServer(t)
	defer ts.Close()

	// 1. Register User & Device
	regBody := []byte(`{
		"username": "tester",
		"password": "secretpassword",
		"displayName": "Tester Account",
		"name": "Desktop PC",
		"fingerprint": "fp_test_123",
		"publicKey": "pk_123"
	}`)
	respReg, err := http.Post(ts.URL+"/auth/v1/register", "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatalf("POST /register: %v", err)
	}
	defer respReg.Body.Close()

	if respReg.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", respReg.StatusCode)
	}

	var regData struct {
		DeviceID string `json:"deviceId"`
		UserID   string `json:"userId"`
		Status   string `json:"status"`
	}
	_ = json.NewDecoder(respReg.Body).Decode(&regData)
	if regData.DeviceID == "" || regData.UserID == "" {
		t.Fatalf("unexpected regData: %+v", regData)
	}

	// 2. Approve device
	now := time.Now().Unix()
	_ = s.UpdateDeviceStatus(t.Context(), regData.DeviceID, "approved", &now)

	// 3. Login
	loginBody := []byte(`{
		"username": "tester",
		"password": "secretpassword",
		"name": "Desktop PC",
		"fingerprint": "fp_test_123"
	}`)
	respLogin, err := http.Post(ts.URL+"/auth/v1/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer respLogin.Body.Close()

	if respLogin.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", respLogin.StatusCode)
	}

	var loginData struct {
		DeviceID string  `json:"deviceId"`
		Status   string  `json:"status"`
		Token    *string `json:"token"`
	}
	_ = json.NewDecoder(respLogin.Body).Decode(&loginData)
	if loginData.Token == nil || *loginData.Token == "" {
		t.Fatalf("expected token after login, got nil")
	}

	// 4. Get Profile
	reqProf, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth/v1/user/profile", nil)
	reqProf.Header.Set("Authorization", "Bearer "+*loginData.Token)
	respProf, err := http.DefaultClient.Do(reqProf)
	if err != nil {
		t.Fatalf("GET /user/profile: %v", err)
	}
	defer respProf.Body.Close()
	if respProf.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", respProf.StatusCode)
	}

	// 5. Update Profile
	upBody := []byte(`{"displayName":"Super Tester"}`)
	reqUp, _ := http.NewRequest(http.MethodPut, ts.URL+"/auth/v1/user/profile", bytes.NewReader(upBody))
	reqUp.Header.Set("Authorization", "Bearer "+*loginData.Token)
	reqUp.Header.Set("Content-Type", "application/json")
	respUp, err := http.DefaultClient.Do(reqUp)
	if err != nil {
		t.Fatalf("PUT /user/profile: %v", err)
	}
	defer respUp.Body.Close()
	if respUp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", respUp.StatusCode)
	}

	// 6. List Devices
	reqDevs, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth/v1/user/devices", nil)
	reqDevs.Header.Set("Authorization", "Bearer "+*loginData.Token)
	respDevs, err := http.DefaultClient.Do(reqDevs)
	if err != nil {
		t.Fatalf("GET /user/devices: %v", err)
	}
	defer respDevs.Body.Close()
	if respDevs.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", respDevs.StatusCode)
	}

	// 7. Verify endpoint returns user and role headers
	reqVer, _ := http.NewRequest(http.MethodGet, ts.URL+"/auth/v1/verify", nil)
	reqVer.Header.Set("Authorization", "Bearer "+*loginData.Token)
	respVer, err := http.DefaultClient.Do(reqVer)
	if err != nil {
		t.Fatalf("GET /verify: %v", err)
	}
	defer respVer.Body.Close()
	if respVer.Header.Get("X-User-Id") != regData.UserID {
		t.Fatalf("expected X-User-Id %s, got %s", regData.UserID, respVer.Header.Get("X-User-Id"))
	}
}
