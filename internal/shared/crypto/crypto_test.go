package crypto

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	if kp.PrivateKey == nil {
		t.Error("Private key is nil")
	}

	if kp.PublicKey == nil {
		t.Error("Public key is nil")
	}

	if len(kp.PrivateKey) != 64 {
		t.Errorf("Expected private key length 64, got %d", len(kp.PrivateKey))
	}

	if len(kp.PublicKey) != 32 {
		t.Errorf("Expected public key length 32, got %d", len(kp.PublicKey))
	}
}

func TestKeyPairStrings(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	pubKeyStr := kp.PublicKeyString()
	if pubKeyStr == "" {
		t.Error("Public key string is empty")
	}

	privKeyStr := kp.PrivateKeyString()
	if privKeyStr == "" {
		t.Error("Private key string is empty")
	}

	kp2, err := LoadFromKeyStrings(pubKeyStr, privKeyStr)
	if err != nil {
		t.Fatalf("Failed to load keypair from strings: %v", err)
	}

	if kp2.PublicKeyString() != pubKeyStr {
		t.Error("Public key strings don't match")
	}
}

func TestSignAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	message := []byte("test message")
	signature := kp.Sign(message)

	if signature == "" {
		t.Error("Signature is empty")
	}

	valid, err := VerifySignature(kp.PublicKeyString(), string(message), signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed")
	}

	invalidMessage := []byte("invalid message")
	valid, err = VerifySignature(kp.PublicKeyString(), string(invalidMessage), signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if valid {
		t.Error("Invalid signature was verified")
	}
}

func TestVerifySignatureInvalidKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	message := []byte("test message")
	signature := kp.Sign(message)

	valid, err := VerifySignature("invalid-public-key", string(message), signature)
	if err == nil {
		t.Error("Expected error for invalid public key")
	}

	if valid {
		t.Error("Invalid public key should not verify signature")
	}
}

func TestGenerateTOTP(t *testing.T) {
	config := TOTPConfig{
		Issuer:      "TestIssuer",
		AccountName: "testuser",
	}

	secret, qr, err := GenerateTOTP(config)
	if err != nil {
		t.Fatalf("Failed to generate TOTP: %v", err)
	}

	if secret == "" {
		t.Error("TOTP secret is empty")
	}

	if qr == "" {
		t.Error("TOTP QR code is empty")
	}

	if len(secret) < 16 {
		t.Errorf("TOTP secret too short: %d", len(secret))
	}
}

func TestValidateTOTP(t *testing.T) {
	config := TOTPConfig{
		Issuer:      "TestIssuer",
		AccountName: "testuser",
	}

	secret, _, err := GenerateTOTP(config)
	if err != nil {
		t.Fatalf("Failed to generate TOTP: %v", err)
	}

	valid := ValidateTOTP(secret, "123456")
	if valid {
		t.Error("Random TOTP code should not be valid")
	}

	valid = ValidateTOTP(secret, "")
	if valid {
		t.Error("Empty TOTP code should not be valid")
	}
}

func TestGetTOTPURL(t *testing.T) {
	config := TOTPConfig{
		Issuer:      "TestIssuer",
		AccountName: "testuser",
	}

	url := GetTOTPURL("JBSWY3DPEHPK3PXP", config)
	if url == "" {
		t.Error("TOTP URL is empty")
	}

	expectedPrefix := "otpauth://totp/TestIssuer:testuser?secret=JBSWY3DPEHPK3PXP"
	if len(url) < len(expectedPrefix) {
		t.Errorf("TOTP URL too short: %s", url)
	}
}

func TestGenerateTOTPQRFromSecret(t *testing.T) {
	config := TOTPConfig{
		Issuer:      "TestIssuer",
		AccountName: "testuser",
	}

	secret := "JBSWY3DPEHPK3PXP"
	qr, err := GenerateTOTPQRFromSecret(secret, config)
	if err != nil {
		t.Fatalf("Failed to generate TOTP QR: %v", err)
	}

	if qr == "" {
		t.Error("TOTP QR code is empty")
	}
}

func TestGenerateDeviceID(t *testing.T) {
	publicKey := "test-public-key-123456"

	deviceID := GenerateDeviceID(publicKey)
	if deviceID == "" {
		t.Error("Device ID is empty")
	}

	if len(deviceID) != 12 {
		t.Errorf("Expected device ID length 12, got %d", len(deviceID))
	}

	deviceID2 := GenerateDeviceID(publicKey)
	if deviceID != deviceID2 {
		t.Error("Device ID should be consistent for same public key")
	}

	publicKey2 := "different-public-key-789"
	deviceID3 := GenerateDeviceID(publicKey2)
	if deviceID3 == deviceID {
		t.Error("Device IDs should be different for different public keys")
	}
}

func TestGenerateRandomSecret(t *testing.T) {
	secret, err := GenerateRandomSecret(32)
	if err != nil {
		t.Fatalf("Failed to generate random secret: %v", err)
	}

	if secret == "" {
		t.Error("Secret is empty")
	}

	if len(secret) < 32 {
		t.Errorf("Secret too short: %d", len(secret))
	}

	secret2, err := GenerateRandomSecret(32)
	if err != nil {
		t.Fatalf("Failed to generate random secret: %v", err)
	}

	if secret == secret2 {
		t.Error("Secrets should be different")
	}
}

func TestLoadFromKeyStrings(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	pubKeyStr := kp.PublicKeyString()
	privKeyStr := kp.PrivateKeyString()

	kp2, err := LoadFromKeyStrings(pubKeyStr, privKeyStr)
	if err != nil {
		t.Fatalf("Failed to load keypair from strings: %v", err)
	}

	if kp2.PublicKeyString() != pubKeyStr {
		t.Error("Public keys don't match")
	}

	if kp2.PrivateKeyString() != privKeyStr {
		t.Error("Private keys don't match")
	}

	message := []byte("test message")
	sig1 := kp.Sign(message)
	sig2 := kp2.Sign(message)

	if sig1 != sig2 {
		t.Error("Signatures from same keys don't match")
	}
}

func TestLoadFromKeyStringsInvalid(t *testing.T) {
	_, err := LoadFromKeyStrings("invalid-base64", "invalid-base64")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	_, err = LoadFromKeyStrings("", "")
	if err == nil {
		t.Error("Expected error for empty strings")
	}
}
