package db

import (
	"fmt"
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
	tmpPath := tmpfile.Name()
	tmpfile.Close()

	db, err := New(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		t.Fatal(err)
	}

	t.Cleanup(func() {
		db.Close()
		os.Remove(tmpPath)
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

func TestDatabasePragmas(t *testing.T) {
	database := setupTestDB(t)

	var journalMode string
	err := database.DB().QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	if err != nil {
		t.Fatalf("failed to query journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("expected journal_mode=wal, got %s", journalMode)
	}

	var busyTimeout int
	err = database.DB().QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout)
	if err != nil {
		t.Fatalf("failed to query busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Errorf("expected busy_timeout=5000, got %d", busyTimeout)
	}

	var foreignKeys int
	err = database.DB().QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys)
	if err != nil {
		t.Fatalf("failed to query foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Errorf("expected foreign_keys=1, got %d", foreignKeys)
	}
}

func TestRevokeDeviceTokensAtomic(t *testing.T) {
	database := setupTestDB(t)

	device := &protocol.DeviceInfo{
		ID: "atomic-test", Name: "test", PublicKey: "pk-atomic",
		Hostname: "host", OS: "linux", Status: protocol.DeviceStatusApproved,
		CreatedAt: time.Now(),
	}
	if err := database.CreateDevice(device, "secret"); err != nil {
		t.Fatal(err)
	}

	expires := time.Now().Add(1 * time.Hour)
	for i := 0; i < 3; i++ {
		sid := fmt.Sprintf("session-%d", i)
		th := fmt.Sprintf("token-hash-%d", i)
		if err := database.CreateSession(sid, "atomic-test", th, expires, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
	}

	if err := database.RevokeDeviceTokens("atomic-test"); err != nil {
		t.Fatalf("RevokeDeviceTokens failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		th := fmt.Sprintf("token-hash-%d", i)
		revoked, err := database.IsTokenRevoked(th)
		if err != nil {
			t.Fatalf("IsTokenRevoked failed: %v", err)
		}
		if !revoked {
			t.Errorf("token %s should be revoked", th)
		}
	}

	sessions, err := database.GetActiveSessions()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sessions {
		if s["device_id"] == "atomic-test" {
			t.Error("sessions for device should have been deleted")
		}
	}
}

func TestUpdateDeviceStatusNonexistent(t *testing.T) {
	database := setupTestDB(t)

	err := database.UpdateDeviceStatus("nonexistent-id", protocol.DeviceStatusApproved)
	if err == nil {
		t.Error("expected error for nonexistent device, got nil")
	}
}

func TestListDevicesRowsErr(t *testing.T) {
	database := setupTestDB(t)

	device := &protocol.DeviceInfo{
		ID: "test-rows-err", Name: "test", PublicKey: "pk-rows-err",
		Hostname: "host", OS: "linux", Status: protocol.DeviceStatusPending,
		CreatedAt: time.Now(),
	}
	if err := database.CreateDevice(device, "secret"); err != nil {
		t.Fatal(err)
	}

	devices, err := database.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices failed: %v", err)
	}
	if len(devices) != 1 {
		t.Errorf("expected 1 device, got %d", len(devices))
	}
}

func TestCreateAndGetUser(t *testing.T) {
	database := setupTestDB(t)

	err := database.CreateUser("user-1", "alice", "totp-secret-123")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	user, err := database.GetUser("user-1")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if user.Name != "alice" {
		t.Errorf("expected name alice, got %s", user.Name)
	}
}

func TestGetUserByName(t *testing.T) {
	database := setupTestDB(t)

	if err := database.CreateUser("user-2", "bob", "secret"); err != nil {
		t.Fatal(err)
	}

	user, err := database.GetUserByName("bob")
	if err != nil {
		t.Fatalf("GetUserByName failed: %v", err)
	}
	if user.ID != "user-2" {
		t.Errorf("expected ID user-2, got %s", user.ID)
	}

	user, err = database.GetUserByName("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != nil {
		t.Error("expected nil for nonexistent user")
	}
}

func TestMarkUserTOTPConfigured(t *testing.T) {
	database := setupTestDB(t)

	if err := database.CreateUser("user-totp", "charlie", "secret"); err != nil {
		t.Fatal(err)
	}

	changed, err := database.MarkUserTOTPConfigured("user-totp")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected first MarkUserTOTPConfigured to return true")
	}

	changed, err = database.MarkUserTOTPConfigured("user-totp")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("expected second MarkUserTOTPConfigured to return false")
	}
}

func TestConsumeTOTPEnrollment(t *testing.T) {
	database := setupTestDB(t)

	if err := database.CreateUser("enroll-user", "dave", "totp-secret"); err != nil {
		t.Fatal(err)
	}
	device := &protocol.DeviceInfo{
		ID: "enroll-device", Name: "test", PublicKey: "pk-enroll",
		Hostname: "host", OS: "linux", Status: protocol.DeviceStatusApproved,
		CreatedAt: time.Now(),
	}
	if err := database.CreateDevice(device, ""); err != nil {
		t.Fatal(err)
	}
	if err := database.SetDeviceUserID("enroll-device", "enroll-user"); err != nil {
		t.Fatal(err)
	}

	codeHash := "test-code-hash"
	expires := time.Now().Add(10 * time.Minute)
	if err := database.CreateTOTPEnrollment(codeHash, "enroll-device", "enroll-user", expires); err != nil {
		t.Fatal(err)
	}

	// ConsumeTOTPEnrollment returns userID (not TOTP secret)
	userID, err := database.ConsumeTOTPEnrollment(codeHash, "enroll-device")
	if err != nil {
		t.Fatalf("ConsumeTOTPEnrollment failed: %v", err)
	}
	if userID != "enroll-user" {
		t.Errorf("expected userID enroll-user, got %s", userID)
	}

	// Second consumption should fail (one-time use)
	_, err = database.ConsumeTOTPEnrollment(codeHash, "enroll-device")
	if err == nil {
		t.Error("expected error on second consumption (one-time use)")
	}
}

func TestConsumeTOTPEnrollmentExpired(t *testing.T) {
	database := setupTestDB(t)

	if err := database.CreateUser("exp-user", "eve", "secret"); err != nil {
		t.Fatal(err)
	}
	device := &protocol.DeviceInfo{
		ID: "exp-device", Name: "test", PublicKey: "pk-exp",
		Hostname: "host", OS: "linux", Status: protocol.DeviceStatusApproved,
		CreatedAt: time.Now(),
	}
	if err := database.CreateDevice(device, ""); err != nil {
		t.Fatal(err)
	}
	if err := database.SetDeviceUserID("exp-device", "exp-user"); err != nil {
		t.Fatal(err)
	}

	codeHash := "expired-code-hash"
	expires := time.Now().Add(-1 * time.Minute)
	if err := database.CreateTOTPEnrollment(codeHash, "exp-device", "exp-user", expires); err != nil {
		t.Fatal(err)
	}

	_, err := database.ConsumeTOTPEnrollment(codeHash, "exp-device")
	if err == nil {
		t.Error("expected error for expired enrollment code")
	}
}

func TestGetDeviceNonExistent(t *testing.T) {
	database := setupTestDB(t)

	device, err := database.GetDevice("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if device != nil {
		t.Error("expected nil for nonexistent device")
	}
}

func TestCreateDeviceDuplicateID(t *testing.T) {
	database := setupTestDB(t)

	device := &protocol.DeviceInfo{
		ID: "dup-id", Name: "test1", PublicKey: "pk-1",
		Hostname: "host", OS: "linux", Status: protocol.DeviceStatusPending,
		CreatedAt: time.Now(),
	}
	if err := database.CreateDevice(device, "secret"); err != nil {
		t.Fatal(err)
	}

	device2 := &protocol.DeviceInfo{
		ID: "dup-id", Name: "test2", PublicKey: "pk-2",
		Hostname: "host", OS: "linux", Status: protocol.DeviceStatusPending,
		CreatedAt: time.Now(),
	}
	err := database.CreateDevice(device2, "secret")
	if err == nil {
		t.Error("expected error for duplicate device ID")
	}
}
