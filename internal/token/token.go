package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

type Token struct {
	Token     string `json:"token"`
	DeviceID  string `json:"deviceId"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt *int64 `json:"expiresAt,omitempty"`
}

func Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto rand failed: %w", err)
	}
	return "tok_" + hex.EncodeToString(b), nil
}
