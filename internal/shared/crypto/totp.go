package crypto

import (
	"encoding/base64"
	"fmt"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// TOTPConfig configuración para TOTP
type TOTPConfig struct {
	Issuer      string
	AccountName string
}

// GenerateTOTP genera un nuevo secreto TOTP y su QR code
func GenerateTOTP(config TOTPConfig) (secret string, qrBase64 string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      config.Issuer,
		AccountName: config.AccountName,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
		Period:      30,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP: %w", err)
	}

	// Generar QR code
	qr, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate QR code: %w", err)
	}

	return key.Secret(), base64.StdEncoding.EncodeToString(qr), nil
}

// ValidateTOTP valida un código TOTP contra un secreto
func ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GetTOTPURL genera la URL para el QR code
func GetTOTPURL(secret string, config TOTPConfig) string {
	key, err := otp.NewKeyFromURL(fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		config.Issuer,
		config.AccountName,
		secret,
		config.Issuer,
	))
	if err != nil {
		return ""
	}
	return key.URL()
}
