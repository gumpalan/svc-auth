-- +goose Up
ALTER TABLE auth_devices ADD COLUMN fingerprint VARCHAR(255) NULL;
CREATE UNIQUE INDEX idx_auth_devices_fingerprint ON auth_devices (fingerprint) WHERE fingerprint IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_auth_devices_fingerprint;
ALTER TABLE auth_devices DROP COLUMN fingerprint;
