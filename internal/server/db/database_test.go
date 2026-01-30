package db

import (
	"os"
	"testing"
	"time"

	"github.com/zyrak/zcloud/internal/shared/protocol"
)

func setupTestDB(t *testing.T) *Database {
	tmpfile, err := os.CreateTemp("", "zcloud-test-*.db")
	if err != nil {
		t.Fatal(err)
	}

	db, err := New(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		db.Close()
		os.Remove(tmpfile.Name())
	})

	return db
}

func TestCreateAndGetDevice(t *testing.T) {
	db := setupTestDB(t)

	device := &protocol.DeviceInfo{
		ID:        "test-device-id",
		Name:      "Test Device",
		PublicKey: "test-public-key",
		Hostname:  "test-host",
		OS:        "linux/amd64",
		Status:    protocol.DeviceStatusPending,
		CreatedAt: time.Now(),
	}

	err := db.CreateDevice(device, "totp-secret")
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	retrieved, err := db.GetDevice(device.ID)
	if err != nil {
		t.Fatalf("Failed to get device: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Device not found")
	}

	if retrieved.ID != device.ID {
		t.Errorf("Expected ID %s, got %s", device.ID, retrieved.ID)
	}

	if retrieved.Name != device.Name {
		t.Errorf("Expected Name %s, got %s", device.Name, retrieved.Name)
	}
}

func TestGetDeviceByPublicKey(t *testing.T) {
	db := setupTestDB(t)

	device := &protocol.DeviceInfo{
		ID:        "test-device-id-2",
		Name:      "Test Device 2",
		PublicKey: "test-public-key-2",
		Status:    protocol.DeviceStatusApproved,
		CreatedAt: time.Now(),
	}

	err := db.CreateDevice(device, "totp-secret-2")
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	retrieved, err := db.GetDeviceByPublicKey("test-public-key-2")
	if err != nil {
		t.Fatalf("Failed to get device by public key: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Device not found")
	}

	if retrieved.ID != device.ID {
		t.Errorf("Expected ID %s, got %s", device.ID, retrieved.ID)
	}
}

func TestUpdateDeviceStatus(t *testing.T) {
	db := setupTestDB(t)

	device := &protocol.DeviceInfo{
		ID:        "test-device-id-3",
		Name:      "Test Device 3",
		PublicKey: "test-public-key-3",
		Status:    protocol.DeviceStatusPending,
		CreatedAt: time.Now(),
	}

	err := db.CreateDevice(device, "totp-secret-3")
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	err = db.UpdateDeviceStatus(device.ID, protocol.DeviceStatusApproved)
	if err != nil {
		t.Fatalf("Failed to update device status: %v", err)
	}

	retrieved, err := db.GetDevice(device.ID)
	if err != nil {
		t.Fatalf("Failed to get device: %v", err)
	}

	if retrieved.Status != protocol.DeviceStatusApproved {
		t.Errorf("Expected status %s, got %s", protocol.DeviceStatusApproved, retrieved.Status)
	}
}

func TestCreateSession(t *testing.T) {
	db := setupTestDB(t)

	device := &protocol.DeviceInfo{
		ID:        "test-device-id-4",
		Name:      "Test Device 4",
		PublicKey: "test-public-key-4",
		Status:    protocol.DeviceStatusApproved,
		CreatedAt: time.Now(),
	}

	err := db.CreateDevice(device, "totp-secret-4")
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	sessionID := "test-session-id"
	tokenHash := "test-token-hash"
	expiresAt := time.Now().Add(12 * time.Hour)

	err = db.CreateSession(sessionID, device.ID, tokenHash, expiresAt, "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	sessions, err := db.GetActiveSessions()
	if err != nil {
		t.Fatalf("Failed to get active sessions: %v", err)
	}

	if len(sessions) == 0 {
		t.Fatal("No active sessions found")
	}

	if sessions[0]["id"] != sessionID {
		t.Errorf("Expected session ID %s, got %s", sessionID, sessions[0]["id"])
	}
}

func TestDeleteDeviceSessions(t *testing.T) {
	db := setupTestDB(t)

	device := &protocol.DeviceInfo{
		ID:        "test-device-id-5",
		Name:      "Test Device 5",
		PublicKey: "test-public-key-5",
		Status:    protocol.DeviceStatusApproved,
		CreatedAt: time.Now(),
	}

	err := db.CreateDevice(device, "totp-secret-5")
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	sessionID := "test-session-id-2"
	tokenHash := "test-token-hash-2"
	expiresAt := time.Now().Add(12 * time.Hour)

	err = db.CreateSession(sessionID, device.ID, tokenHash, expiresAt, "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = db.DeleteDeviceSessions(device.ID)
	if err != nil {
		t.Fatalf("Failed to delete device sessions: %v", err)
	}

	sessions, err := db.GetActiveSessions()
	if err != nil {
		t.Fatalf("Failed to get active sessions: %v", err)
	}

	if len(sessions) > 0 {
		t.Error("Expected no sessions after deletion")
	}
}

func TestListDevices(t *testing.T) {
	db := setupTestDB(t)

	for i := 0; i < 3; i++ {
		device := &protocol.DeviceInfo{
			ID:        "test-device-id-list-" + string(rune('a'+i)),
			Name:      "Test Device " + string(rune('a'+i)),
			PublicKey: "test-public-key-list-" + string(rune('a'+i)),
			Status:    protocol.DeviceStatusApproved,
			CreatedAt: time.Now(),
		}

		err := db.CreateDevice(device, "totp-secret-list-"+string(rune('a'+i)))
		if err != nil {
			t.Fatalf("Failed to create device: %v", err)
		}
	}

	devices, err := db.ListDevices()
	if err != nil {
		t.Fatalf("Failed to list devices: %v", err)
	}

	if len(devices) < 3 {
		t.Errorf("Expected at least 3 devices, got %d", len(devices))
	}
}

func TestSetAdmin(t *testing.T) {
	db := setupTestDB(t)

	device := &protocol.DeviceInfo{
		ID:        "test-device-id-admin",
		Name:      "Test Device Admin",
		PublicKey: "test-public-key-admin",
		Status:    protocol.DeviceStatusApproved,
		CreatedAt: time.Now(),
	}

	err := db.CreateDevice(device, "totp-secret-admin")
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	err = db.SetAdmin(device.ID, true)
	if err != nil {
		t.Fatalf("Failed to set admin: %v", err)
	}

	isAdmin, err := db.IsAdmin(device.ID)
	if err != nil {
		t.Fatalf("Failed to check admin: %v", err)
	}

	if !isAdmin {
		t.Error("Expected device to be admin")
	}

	err = db.SetAdmin(device.ID, false)
	if err != nil {
		t.Fatalf("Failed to unset admin: %v", err)
	}

	isAdmin, err = db.IsAdmin(device.ID)
	if err != nil {
		t.Fatalf("Failed to check admin: %v", err)
	}

	if isAdmin {
		t.Error("Expected device to not be admin")
	}
}

func TestCleanExpiredSessions(t *testing.T) {
	db := setupTestDB(t)

	device := &protocol.DeviceInfo{
		ID:        "test-device-id-cleanup",
		Name:      "Test Device Cleanup",
		PublicKey: "test-public-key-cleanup",
		Status:    protocol.DeviceStatusApproved,
		CreatedAt: time.Now(),
	}

	err := db.CreateDevice(device, "totp-secret-cleanup")
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	sessionID := "test-session-id-expired"
	tokenHash := "test-token-hash-expired"
	expiresAt := time.Now().Add(-1 * time.Hour)

	err = db.CreateSession(sessionID, device.ID, tokenHash, expiresAt, "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = db.CleanExpiredSessions()
	if err != nil {
		t.Fatalf("Failed to clean expired sessions: %v", err)
	}

	sessions, err := db.GetActiveSessions()
	if err != nil {
		t.Fatalf("Failed to get active sessions: %v", err)
	}

	if len(sessions) > 0 {
		t.Error("Expected no active sessions after cleanup")
	}
}

func TestRevokeToken(t *testing.T) {
	db := setupTestDB(t)

	tokenHash := "test-token-hash-revoke"
	expiresAt := time.Now().Add(12 * time.Hour)

	err := db.RevokeToken(tokenHash, expiresAt, "test_reason")
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	revoked, err := db.IsTokenRevoked(tokenHash)
	if err != nil {
		t.Fatalf("Failed to check token revocation: %v", err)
	}

	if !revoked {
		t.Error("Expected token to be revoked")
	}
}

func TestIsTokenRevoked(t *testing.T) {
	db := setupTestDB(t)

	tokenHash := "test-token-hash-check-1"
	expiresAt := time.Now().Add(12 * time.Hour)

	revoked, err := db.IsTokenRevoked(tokenHash)
	if err != nil {
		t.Fatalf("Failed to check token revocation: %v", err)
	}

	if revoked {
		t.Error("Expected token not to be revoked")
	}

	err = db.RevokeToken(tokenHash, expiresAt, "test")
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	revoked, err = db.IsTokenRevoked(tokenHash)
	if err != nil {
		t.Fatalf("Failed to check token revocation: %v", err)
	}

	if !revoked {
		t.Error("Expected token to be revoked")
	}
}

func TestRevokeDeviceTokens(t *testing.T) {
	db := setupTestDB(t)

	device := &protocol.DeviceInfo{
		ID:        "test-device-id-revoke-tokens",
		Name:      "Test Device Revoke Tokens",
		PublicKey: "test-public-key-revoke-tokens",
		Status:    protocol.DeviceStatusApproved,
		CreatedAt: time.Now(),
	}

	err := db.CreateDevice(device, "totp-secret-revoke-tokens")
	if err != nil {
		t.Fatalf("Failed to create device: %v", err)
	}

	sessionID := "test-session-id-revoke"
	tokenHash := "test-token-hash-revoke"
	expiresAt := time.Now().Add(12 * time.Hour)

	err = db.CreateSession(sessionID, device.ID, tokenHash, expiresAt, "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	err = db.RevokeDeviceTokens(device.ID)
	if err != nil {
		t.Fatalf("Failed to revoke device tokens: %v", err)
	}

	revoked, err := db.IsTokenRevoked(tokenHash)
	if err != nil {
		t.Fatalf("Failed to check token revocation: %v", err)
	}

	if !revoked {
		t.Error("Expected token to be revoked")
	}
}
