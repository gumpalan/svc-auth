-- +goose Up
CREATE TABLE auth_roles (
  id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(64) NOT NULL UNIQUE,
  description VARCHAR(255) NULL,
  allowed_modules TEXT NOT NULL,
  created_at BIGINT NOT NULL
);

CREATE TABLE auth_users (
  id VARCHAR(64) PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role_id VARCHAR(64) NOT NULL,
  display_name VARCHAR(128) NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

CREATE INDEX idx_auth_users_role_id ON auth_users (role_id);

ALTER TABLE auth_devices ADD COLUMN user_id VARCHAR(64) NULL;
CREATE INDEX idx_auth_devices_user_id ON auth_devices (user_id);

-- Seed peran bawaan: admin akses semua modul, user akses modul iot
INSERT INTO auth_roles (id, name, description, allowed_modules, created_at)
VALUES
  ('role_admin', 'admin', 'Administrator sistem dengan hak akses penuh', '["*"]', 1700000000),
  ('role_user', 'user', 'Pengguna reguler modul IoT', '["iot"]', 1700000000);

-- +goose Down
DROP INDEX IF EXISTS idx_auth_devices_user_id;
ALTER TABLE auth_devices DROP COLUMN user_id;
DROP TABLE IF EXISTS auth_users;
DROP TABLE IF EXISTS auth_roles;
