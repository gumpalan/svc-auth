-- +goose Up
CREATE TABLE auth_tokens (
  token VARCHAR(128) PRIMARY KEY,
  device_id VARCHAR(64) NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NULL
);

-- +goose Down
DROP TABLE auth_tokens;
