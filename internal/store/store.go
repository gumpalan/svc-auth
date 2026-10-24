package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/gumpalan/svc-auth/internal/database"
	"github.com/gumpalan/svc-auth/internal/device"
	"github.com/gumpalan/svc-auth/internal/token"
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

func (s *Store) CreateDevice(ctx context.Context, dev *device.Device) error {
	q := database.Rebind(s.dialect, `
		INSERT INTO auth_devices (id, name, public_key, status, created_at, approved_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	_, err := s.db.ExecContext(ctx, q, dev.ID, dev.Name, dev.PublicKey, string(dev.Status), dev.CreatedAt, dev.ApprovedAt)
	if err != nil {
		return fmt.Errorf("insert auth_devices: %w", err)
	}
	return nil
}

func (s *Store) GetDevice(ctx context.Context, id string) (*device.Device, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, name, public_key, status, created_at, approved_at
		FROM auth_devices
		WHERE id = ?
	`)
	row := s.db.QueryRowContext(ctx, q, id)

	var dev device.Device
	var st string
	var appAt sql.NullInt64
	if err := row.Scan(&dev.ID, &dev.Name, &dev.PublicKey, &st, &dev.CreatedAt, &appAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan auth_device: %w", err)
	}
	dev.Status = device.Status(st)
	if appAt.Valid {
		v := appAt.Int64
		dev.ApprovedAt = &v
	}
	return &dev, nil
}

func (s *Store) ListDevices(ctx context.Context) ([]device.Device, error) {
	q := database.Rebind(s.dialect, `
		SELECT id, name, public_key, status, created_at, approved_at
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
		var dev device.Device
		var st string
		var appAt sql.NullInt64
		if err := rows.Scan(&dev.ID, &dev.Name, &dev.PublicKey, &st, &dev.CreatedAt, &appAt); err != nil {
			return nil, fmt.Errorf("scan list auth_device: %w", err)
		}
		dev.Status = device.Status(st)
		if appAt.Valid {
			v := appAt.Int64
			dev.ApprovedAt = &v
		}
		list = append(list, dev)
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
		SELECT d.id, d.name, d.public_key, d.status, d.created_at, d.approved_at
		FROM auth_tokens t
		JOIN auth_devices d ON t.device_id = d.id
		WHERE t.token = ? AND (t.expires_at IS NULL OR t.expires_at > ?)
	`)
	now := time.Now().Unix()
	row := s.db.QueryRowContext(ctx, q, tokStr, now)

	var dev device.Device
	var st string
	var appAt sql.NullInt64
	if err := row.Scan(&dev.ID, &dev.Name, &dev.PublicKey, &st, &dev.CreatedAt, &appAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan device by token: %w", err)
	}
	dev.Status = device.Status(st)
	if appAt.Valid {
		v := appAt.Int64
		dev.ApprovedAt = &v
	}
	return &dev, nil
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
