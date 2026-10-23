-- +goose Up
-- Status bernilai pending, approved, atau revoked.
CREATE TABLE auth_devices (
  id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  public_key TEXT NOT NULL,
  status VARCHAR(16) NOT NULL,
  created_at BIGINT NOT NULL,
  approved_at BIGINT NULL
);

-- +goose Down
DROP TABLE auth_devices;
