package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gumpalan/svc-auth/internal/database"
	"github.com/gumpalan/svc-auth/internal/device"
	"github.com/gumpalan/svc-auth/internal/token"
	"github.com/gumpalan/svc-auth/internal/user"
)

var (
	ErrNotFound = errors.New("record not found")
)

type Store struct {
	db      *sql.DB
	dialect database.Dialect
}

func New(db *sql.DB, dialect database.Dialect) *Store {
	return &Store{
		db:      db,
		dialect: dialect,
	}
}

// ----------------- Perangkat (Devices) -----------------

func (s *Store) CreateDevice(ctx context.Context, dev *device.Device) error {
	q := database.Rebind(s.dialect, `
		INSERT INTO auth_devices (id, name, fingerprint, public_key, status, created_at, approved_at, user_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	fp := sql.NullString{String: dev.Fingerprint, Valid: dev.Fingerprint != ""}
	var uID sql.NullString
	if dev.UserID != nil && *dev.UserID != "" {
		uID = sql.NullString{String: *dev.UserID, Valid: true}
	}
	_, err := s.db.ExecContext(ctx, q, dev.ID, dev.Name, fp, dev.PublicKey, string(dev.Status), dev.CreatedAt, dev.ApprovedAt, uID)
	if err != nil {
		return fmt.Errorf("insert auth_devices: %w", err)
	}
	return nil
}

func scanDevice(row interface{ Scan(...any) error }) (*device.Device, error) {
	var dev device.Device
	var st string
	var appAt sql.NullInt64
	var fp sql.NullString
	var uID sql.NullString
	if err := row.Scan(&dev.ID, &dev.Name, &fp, &dev.PublicKey, &st, &dev.CreatedAt, &appAt, &uID); err != nil {
		return nil, err
	}
	dev.Status = device.Status(st)
	dev.Fingerprint = fp.String
	if appAt.Valid {
		v := appAt.Int64
		dev.ApprovedAt = &v
	}
	if uID.Valid {
		dev.UserID = &uID.String
	}
	return &dev, nil
}

func (s *Store) GetDevice(ctx context.Context, id string) (*device.Device, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, name, fingerprint, public_key, status, created_at, approved_at, user_id
		FROM auth_devices
		WHERE id = ?
	`)
	row := s.db.QueryRowContext(ctx, q, id)
	dev, err := scanDevice(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan auth_device: %w", err)
	}
	return dev, nil
}

func (s *Store) GetDeviceByFingerprint(ctx context.Context, fingerprint string) (*device.Device, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, name, fingerprint, public_key, status, created_at, approved_at, user_id
		FROM auth_devices
		WHERE fingerprint = ?
	`)
	row := s.db.QueryRowContext(ctx, q, fingerprint)
	dev, err := scanDevice(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan auth_device by fingerprint: %w", err)
	}
	return dev, nil
}

func (s *Store) ListDevices(ctx context.Context) ([]device.Device, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, name, fingerprint, public_key, status, created_at, approved_at, user_id
		FROM auth_devices
		ORDER BY created_at DESC
	`)
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query auth_devices: %w", err)
	}
	defer rows.Close()

	var list []device.Device
	for rows.Next() {
		dev, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("scan list auth_device: %w", err)
		}
		list = append(list, *dev)
	}
	return list, rows.Err()
}

func (s *Store) ListDevicesByUserID(ctx context.Context, userID string) ([]device.Device, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, name, fingerprint, public_key, status, created_at, approved_at, user_id
		FROM auth_devices
		WHERE user_id = ?
		ORDER BY created_at DESC
	`)
	rows, err := s.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("query auth_devices by user: %w", err)
	}
	defer rows.Close()

	var list []device.Device
	for rows.Next() {
		dev, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("scan list auth_device: %w", err)
		}
		list = append(list, *dev)
	}
	return list, rows.Err()
}

func (s *Store) UpdateDeviceStatus(ctx context.Context, id string, st device.Status, approvedAt *int64) error {
	q := database.Rebind(s.dialect, `
		UPDATE auth_devices
		SET status = ?, approved_at = ?
		WHERE id = ?
	`)
	res, err := s.db.ExecContext(ctx, q, string(st), approvedAt, id)
	if err != nil {
		return fmt.Errorf("update auth_device status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdateDeviceUserID(ctx context.Context, deviceID, userID string) error {
	q := database.Rebind(s.dialect, `
		UPDATE auth_devices
		SET user_id = ?
		WHERE id = ?
	`)
	res, err := s.db.ExecContext(ctx, q, userID, deviceID)
	if err != nil {
		return fmt.Errorf("update auth_device user_id: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RevokeDeviceByUser(ctx context.Context, deviceID, userID string) error {
	q := database.Rebind(s.dialect, `
		UPDATE auth_devices
		SET status = ?
		WHERE id = ? AND user_id = ?
	`)
	res, err := s.db.ExecContext(ctx, q, string(device.StatusRevoked), deviceID, userID)
	if err != nil {
		return fmt.Errorf("revoke auth_device: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return s.RevokeTokensByDeviceID(ctx, deviceID)
}

// ----------------- Token (Tokens) -----------------

func (s *Store) CreateToken(ctx context.Context, tok *token.Token) error {
	q := database.Rebind(s.dialect, `
		INSERT INTO auth_tokens (token, device_id, created_at, expires_at)
		VALUES (?, ?, ?, ?)
	`)
	_, err := s.db.ExecContext(ctx, q, tok.Token, tok.DeviceID, tok.CreatedAt, tok.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert auth_token: %w", err)
	}
	return nil
}

func (s *Store) GetTokenByDeviceID(ctx context.Context, deviceID string) (*token.Token, error) {
	q := database.Rebind(s.dialect, `
		SELECT token, device_id, created_at, expires_at
		FROM auth_tokens
		WHERE device_id = ?
		ORDER BY created_at DESC
	`)
	row := s.db.QueryRowContext(ctx, q, deviceID)

	var tok token.Token
	var exp sql.NullInt64
	if err := row.Scan(&tok.Token, &tok.DeviceID, &tok.CreatedAt, &exp); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan auth_token: %w", err)
	}
	if exp.Valid {
		v := exp.Int64
		tok.ExpiresAt = &v
	}
	return &tok, nil
}

func (s *Store) GetDeviceByToken(ctx context.Context, tokStr string) (*device.Device, error) {
	q := database.Rebind(s.dialect, `
		SELECT d.id, d.name, d.fingerprint, d.public_key, d.status, d.created_at, d.approved_at, d.user_id
		FROM auth_tokens t
		JOIN auth_devices d ON t.device_id = d.id
		WHERE t.token = ? AND (t.expires_at IS NULL OR t.expires_at > ?)
	`)
	now := time.Now().Unix()
	row := s.db.QueryRowContext(ctx, q, tokStr, now)
	dev, err := scanDevice(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan device by token: %w", err)
	}
	return dev, nil
}

func (s *Store) RevokeTokensByDeviceID(ctx context.Context, deviceID string) error {
	q := database.Rebind(s.dialect, `
		DELETE FROM auth_tokens
		WHERE device_id = ?
	`)
	_, err := s.db.ExecContext(ctx, q, deviceID)
	if err != nil {
		return fmt.Errorf("delete auth_tokens: %w", err)
	}
	return nil
}

// ----------------- Peran (Roles) -----------------

func (s *Store) CreateRole(ctx context.Context, r *user.Role) error {
	modulesBytes, err := json.Marshal(r.AllowedModules)
	if err != nil {
		return fmt.Errorf("marshal allowed_modules: %w", err)
	}

	q := database.Rebind(s.dialect, `
		INSERT INTO auth_roles (id, name, description, allowed_modules, created_at)
		VALUES (?, ?, ?, ?, ?)
	`)
	_, err = s.db.ExecContext(ctx, q, r.ID, r.Name, r.Description, string(modulesBytes), r.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert auth_roles: %w", err)
	}
	return nil
}

func scanRole(row interface{ Scan(...any) error }) (*user.Role, error) {
	var r user.Role
	var desc sql.NullString
	var modsRaw string
	if err := row.Scan(&r.ID, &r.Name, &desc, &modsRaw, &r.CreatedAt); err != nil {
		return nil, err
	}
	r.Description = desc.String
	if modsRaw != "" {
		_ = json.Unmarshal([]byte(modsRaw), &r.AllowedModules)
	}
	if r.AllowedModules == nil {
		r.AllowedModules = []string{}
	}
	return &r, nil
}

func (s *Store) GetRole(ctx context.Context, id string) (*user.Role, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, name, description, allowed_modules, created_at
		FROM auth_roles
		WHERE id = ?
	`)
	row := s.db.QueryRowContext(ctx, q, id)
	r, err := scanRole(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan auth_role: %w", err)
	}
	return r, nil
}

func (s *Store) GetRoleByName(ctx context.Context, name string) (*user.Role, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, name, description, allowed_modules, created_at
		FROM auth_roles
		WHERE name = ?
	`)
	row := s.db.QueryRowContext(ctx, q, name)
	r, err := scanRole(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan auth_role by name: %w", err)
	}
	return r, nil
}

func (s *Store) ListRoles(ctx context.Context) ([]user.Role, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, name, description, allowed_modules, created_at
		FROM auth_roles
		ORDER BY created_at ASC
	`)
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query auth_roles: %w", err)
	}
	defer rows.Close()

	var list []user.Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, fmt.Errorf("scan auth_role: %w", err)
		}
		list = append(list, *r)
	}
	return list, rows.Err()
}

// ----------------- Pengguna (Users) -----------------

func (s *Store) CreateUser(ctx context.Context, u *user.User) error {
	q := database.Rebind(s.dialect, `
		INSERT INTO auth_users (id, username, password_hash, role_id, display_name, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	disp := sql.NullString{String: u.DisplayName, Valid: u.DisplayName != ""}
	_, err := s.db.ExecContext(ctx, q, u.ID, u.Username, u.PasswordHash, u.RoleID, disp, u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert auth_users: %w", err)
	}
	return nil
}

func scanUser(row interface{ Scan(...any) error }) (*user.User, error) {
	var u user.User
	var disp sql.NullString
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.RoleID, &disp, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	u.DisplayName = disp.String
	return &u, nil
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*user.User, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, username, password_hash, role_id, display_name, created_at, updated_at
		FROM auth_users
		WHERE id = ?
	`)
	row := s.db.QueryRowContext(ctx, q, id)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan auth_user: %w", err)
	}
	// Enrich role
	if r, err := s.GetRole(ctx, u.RoleID); err == nil {
		u.Role = r
	}
	return u, nil
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*user.User, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, username, password_hash, role_id, display_name, created_at, updated_at
		FROM auth_users
		WHERE username = ?
	`)
	row := s.db.QueryRowContext(ctx, q, username)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan auth_user by username: %w", err)
	}
	if r, err := s.GetRole(ctx, u.RoleID); err == nil {
		u.Role = r
	}
	return u, nil
}

func (s *Store) UpdateUserPassword(ctx context.Context, id, passwordHash string) error {
	q := database.Rebind(s.dialect, `
		UPDATE auth_users
		SET password_hash = ?, updated_at = ?
		WHERE id = ?
	`)
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, q, passwordHash, now, id)
	if err != nil {
		return fmt.Errorf("update auth_user password: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdateUserProfile(ctx context.Context, id, displayName string) error {
	q := database.Rebind(s.dialect, `
		UPDATE auth_users
		SET display_name = ?, updated_at = ?
		WHERE id = ?
	`)
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, q, displayName, now, id)
	if err != nil {
		return fmt.Errorf("update auth_user display_name: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListUsers(ctx context.Context) ([]user.User, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, username, password_hash, role_id, display_name, created_at, updated_at
		FROM auth_users
		ORDER BY created_at ASC
	`)
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query auth_users: %w", err)
	}
	defer rows.Close()

	var list []user.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan auth_user: %w", err)
		}
		if r, err := s.GetRole(ctx, u.RoleID); err == nil {
			u.Role = r
		}
		list = append(list, *u)
	}
	return list, rows.Err()
}

// GetUserByToken mengambil identitas User & Role berdasarkan token aktif.
func (s *Store) GetUserByToken(ctx context.Context, tokStr string) (*user.User, *device.Device, error) {
	dev, err := s.GetDeviceByToken(ctx, tokStr)
	if err != nil {
		return nil, nil, err
	}
	if dev.UserID == nil || *dev.UserID == "" {
		return nil, dev, nil
	}
	u, err := s.GetUserByID(ctx, *dev.UserID)
	if err != nil {
		return nil, dev, nil
	}
	return u, dev, nil
}
