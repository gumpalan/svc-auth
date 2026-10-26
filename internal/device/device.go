package device

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRevoked  Status = "revoked"
)

type Device struct {
	ID          string  `json:"deviceId"`
	Name        string  `json:"name"`
	Fingerprint string  `json:"fingerprint"`
	PublicKey   string  `json:"publicKey"`
	Status      Status  `json:"status"`
	CreatedAt   int64   `json:"createdAt"`
	ApprovedAt  *int64  `json:"approvedAt,omitempty"`
	UserID      *string `json:"userId,omitempty"`
}
