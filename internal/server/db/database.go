package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/zyrak/zcloud/internal/shared/protocol"
)

// Database representa la conexión a la base de datos
type Database struct {
	db *sql.DB
}

// New crea una nueva conexión a la base de datos
func New(path string) (*Database, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Crear tablas
	if err := createTables(db); err != nil {
		return nil, err
	}

	return &Database{db: db}, nil
}

// Close cierra la conexión
func (d *Database) Close() error {
	return d.db.Close()
}

func createTables(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS devices (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		public_key TEXT NOT NULL UNIQUE,
		hostname TEXT,
		os TEXT,
		status TEXT NOT NULL DEFAULT 'pending',
		totp_secret TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_access DATETIME,
		is_admin INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		device_id TEXT NOT NULL,
		token_hash TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		ip_address TEXT,
		FOREIGN KEY (device_id) REFERENCES devices(id)
	);

	CREATE TABLE IF NOT EXISTS revoked_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token_hash TEXT NOT NULL UNIQUE,
		revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		reason TEXT,
		expires_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_revoked_tokens_hash ON revoked_tokens(token_hash);
	CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at);
	`

	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	return nil
}

// Device methods

// CreateDevice crea un nuevo dispositivo
func (d *Database) CreateDevice(device *protocol.DeviceInfo, totpSecret string) error {
	_, err := d.db.Exec(`
		INSERT INTO devices (id, name, public_key, hostname, os, status, totp_secret, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, device.ID, device.Name, device.PublicKey, device.Hostname, device.OS, device.Status, totpSecret, device.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create device: %w", err)
	}
	return nil
}

// GetDevice obtiene un dispositivo por ID
func (d *Database) GetDevice(id string) (*protocol.DeviceInfo, error) {
	var device protocol.DeviceInfo
	var lastAccess sql.NullTime

	err := d.db.QueryRow(`
		SELECT id, name, public_key, hostname, os, status, created_at, last_access
		FROM devices WHERE id = ?
	`, id).Scan(&device.ID, &device.Name, &device.PublicKey, &device.Hostname, &device.OS, &device.Status, &device.CreatedAt, &lastAccess)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	if lastAccess.Valid {
		device.LastAccess = lastAccess.Time
	}

	return &device, nil
}

// GetDeviceByPublicKey obtiene un dispositivo por clave pública
func (d *Database) GetDeviceByPublicKey(publicKey string) (*protocol.DeviceInfo, error) {
	var device protocol.DeviceInfo
	var lastAccess sql.NullTime

	err := d.db.QueryRow(`
		SELECT id, name, public_key, hostname, os, status, created_at, last_access
		FROM devices WHERE public_key = ?
	`, publicKey).Scan(&device.ID, &device.Name, &device.PublicKey, &device.Hostname, &device.OS, &device.Status, &device.CreatedAt, &lastAccess)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	if lastAccess.Valid {
		device.LastAccess = lastAccess.Time
	}

	return &device, nil
}

// GetTOTPSecret obtiene el secreto TOTP de un dispositivo
func (d *Database) GetTOTPSecret(deviceID string) (string, error) {
	var secret sql.NullString
	err := d.db.QueryRow(`SELECT totp_secret FROM devices WHERE id = ?`, deviceID).Scan(&secret)
	if err != nil {
		return "", fmt.Errorf("failed to get TOTP secret: %w", err)
	}
	return secret.String, nil
}

// UpdateDeviceStatus actualiza el estado de un dispositivo
func (d *Database) UpdateDeviceStatus(id string, status protocol.DeviceStatus) error {
	_, err := d.db.Exec(`UPDATE devices SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return fmt.Errorf("failed to update device status: %w", err)
	}
	return nil
}

// UpdateDeviceTOTP actualiza el secreto TOTP de un dispositivo
func (d *Database) UpdateDeviceTOTP(id string, totpSecret string) error {
	_, err := d.db.Exec(`UPDATE devices SET totp_secret = ? WHERE id = ?`, totpSecret, id)
	if err != nil {
		return fmt.Errorf("failed to update device TOTP: %w", err)
	}
	return nil
}

// UpdateDeviceLastAccess actualiza el último acceso de un dispositivo
func (d *Database) UpdateDeviceLastAccess(id string) error {
	_, err := d.db.Exec(`UPDATE devices SET last_access = ? WHERE id = ?`, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update device last access: %w", err)
	}
	return nil
}

// ListDevices lista todos los dispositivos
func (d *Database) ListDevices() ([]protocol.DeviceInfo, error) {
	rows, err := d.db.Query(`
		SELECT id, name, public_key, hostname, os, status, created_at, last_access
		FROM devices ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}
	defer rows.Close()

	var devices []protocol.DeviceInfo
	for rows.Next() {
		var device protocol.DeviceInfo
		var lastAccess sql.NullTime

		if err := rows.Scan(&device.ID, &device.Name, &device.PublicKey, &device.Hostname, &device.OS, &device.Status, &device.CreatedAt, &lastAccess); err != nil {
			return nil, fmt.Errorf("failed to scan device: %w", err)
		}

		if lastAccess.Valid {
			device.LastAccess = lastAccess.Time
		}

		devices = append(devices, device)
	}

	return devices, nil
}

// IsAdmin verifica si un dispositivo es admin
func (d *Database) IsAdmin(deviceID string) (bool, error) {
	var isAdmin int
	err := d.db.QueryRow(`SELECT is_admin FROM devices WHERE id = ?`, deviceID).Scan(&isAdmin)
	if err != nil {
		return false, fmt.Errorf("failed to check admin: %w", err)
	}
	return isAdmin == 1, nil
}

// SetAdmin establece un dispositivo como admin
func (d *Database) SetAdmin(deviceID string, isAdmin bool) error {
	val := 0
	if isAdmin {
		val = 1
	}
	_, err := d.db.Exec(`UPDATE devices SET is_admin = ? WHERE id = ?`, val, deviceID)
	if err != nil {
		return fmt.Errorf("failed to set admin: %w", err)
	}
	return nil
}

// Session methods

// CreateSession crea una nueva sesión
func (d *Database) CreateSession(id, deviceID, tokenHash string, expiresAt time.Time, ip string) error {
	_, err := d.db.Exec(`
		INSERT INTO sessions (id, device_id, token_hash, expires_at, ip_address)
		VALUES (?, ?, ?, ?, ?)
	`, id, deviceID, tokenHash, expiresAt, ip)

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

// RevokeDeviceTokens revoca todos los tokens de un dispositivo
func (d *Database) RevokeDeviceTokens(deviceID string) error {
	// Obtener todos los tokens del dispositivo
	rows, err := d.db.Query(`SELECT token_hash, expires_at FROM sessions WHERE device_id = ?`, deviceID)
	if err != nil {
		return fmt.Errorf("failed to query device sessions: %w", err)
	}
	defer rows.Close()

	var tokenHashes []string
	var expiresAts []time.Time

	for rows.Next() {
		var tokenHash string
		var expiresAt time.Time
		if err := rows.Scan(&tokenHash, &expiresAt); err != nil {
			continue
		}
		tokenHashes = append(tokenHashes, tokenHash)
		expiresAts = append(expiresAts, expiresAt)
	}

	// Revocar todos los tokens
	for i, tokenHash := range tokenHashes {
		_ = d.RevokeToken(tokenHash, expiresAts[i], "device_revoked")
	}

	// Eliminar sesiones del dispositivo
	return d.DeleteDeviceSessions(deviceID)
}

// DeleteSession elimina una sesión
func (d *Database) DeleteSession(id string) error {
	_, err := d.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// DeleteDeviceSessions elimina todas las sesiones de un dispositivo
func (d *Database) DeleteDeviceSessions(deviceID string) error {
	_, err := d.db.Exec(`DELETE FROM sessions WHERE device_id = ?`, deviceID)
	if err != nil {
		return fmt.Errorf("failed to delete device sessions: %w", err)
	}
	return nil
}

// CleanExpiredSessions elimina sesiones expiradas
func (d *Database) CleanExpiredSessions() error {
	_, err := d.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now())
	if err != nil {
		return fmt.Errorf("failed to clean expired sessions: %w", err)
	}
	return nil
}

// RevokeToken revoca un token específico
func (d *Database) RevokeToken(tokenHash string, expiresAt time.Time, reason string) error {
	_, err := d.db.Exec(`
		INSERT INTO revoked_tokens (token_hash, revoked_at, reason, expires_at)
		VALUES (?, ?, ?, ?)
	`, tokenHash, time.Now(), reason, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	return nil
}

// IsTokenRevoked verifica si un token está revocado
func (d *Database) IsTokenRevoked(tokenHash string) (bool, error) {
	// Limpiar tokens revocados expirados primero
	_, err := d.db.Exec(`DELETE FROM revoked_tokens WHERE expires_at < ?`, time.Now())
	if err != nil {
		return false, fmt.Errorf("failed to clean expired revoked tokens: %w", err)
	}

	var count int
	err = d.db.QueryRow(`SELECT COUNT(*) FROM revoked_tokens WHERE token_hash = ?`, tokenHash).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check token revocation: %w", err)
	}

	return count > 0, nil
}

// GetActiveSessions obtiene las sesiones activas
func (d *Database) GetActiveSessions() ([]map[string]interface{}, error) {
	rows, err := d.db.Query(`
		SELECT s.id, s.device_id, d.name as device_name, s.created_at, s.expires_at, s.ip_address
		FROM sessions s
		JOIN devices d ON s.device_id = d.id
		WHERE s.expires_at > ?
		ORDER BY s.created_at DESC
	`, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}
	defer rows.Close()

	var sessions []map[string]interface{}
	for rows.Next() {
		var id, deviceID, deviceName, ip string
		var createdAt, expiresAt time.Time

		if err := rows.Scan(&id, &deviceID, &deviceName, &createdAt, &expiresAt, &ip); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}

		sessions = append(sessions, map[string]interface{}{
			"id":          id,
			"device_id":   deviceID,
			"device_name": deviceName,
			"created_at":  createdAt,
			"expires_at":  expiresAt,
			"ip_address":  ip,
		})
	}

	return sessions, nil
}
