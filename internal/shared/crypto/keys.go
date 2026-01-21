package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

// KeyPair representa un par de claves Ed25519
type KeyPair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// GenerateKeyPair genera un nuevo par de claves Ed25519
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}
	return &KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// PublicKeyString devuelve la clave pública en base64
func (kp *KeyPair) PublicKeyString() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey)
}

// PrivateKeyString devuelve la clave privada en base64
func (kp *KeyPair) PrivateKeyString() string {
	return base64.StdEncoding.EncodeToString(kp.PrivateKey)
}

// Sign firma un mensaje con la clave privada
func (kp *KeyPair) Sign(message []byte) string {
	sig := ed25519.Sign(kp.PrivateKey, message)
	return base64.StdEncoding.EncodeToString(sig)
}

// SaveToFiles guarda las claves en archivos
func (kp *KeyPair) SaveToFiles(dir string) error {
	// Crear directorio si no existe
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Guardar clave privada
	privPath := filepath.Join(dir, "device.key")
	if err := os.WriteFile(privPath, []byte(kp.PrivateKeyString()), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Guardar clave pública
	pubPath := filepath.Join(dir, "device.pub")
	if err := os.WriteFile(pubPath, []byte(kp.PublicKeyString()), 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// LoadFromFiles carga las claves desde archivos
func LoadFromFiles(dir string) (*KeyPair, error) {
	// Leer clave privada
	privPath := filepath.Join(dir, "device.key")
	privData, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(string(privData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}

	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)

	return &KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// VerifySignature verifica una firma con una clave pública
func VerifySignature(publicKeyB64, message, signatureB64 string) (bool, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}

	if len(pubBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	pub := ed25519.PublicKey(pubBytes)
	return ed25519.Verify(pub, []byte(message), sigBytes), nil
}

// GenerateDeviceID genera un ID único para el dispositivo basado en la clave pública
func GenerateDeviceID(publicKey string) string {
	// Usar los primeros 8 caracteres del hash de la clave pública
	hash := base64.StdEncoding.EncodeToString([]byte(publicKey))
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

// GenerateRandomSecret genera un secreto aleatorio para JWT
func GenerateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}
