package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
)

const enrollmentAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func GenerateEnrollmentCode() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate enrollment code: %w", err)
	}
	out := make([]byte, 12)
	for i, v := range b {
		out[i] = enrollmentAlphabet[int(v)%len(enrollmentAlphabet)]
	}
	code := fmt.Sprintf("%s-%s-%s", string(out[0:4]), string(out[4:8]), string(out[8:12]))
	return code, nil
}

func HashEnrollmentCode(code string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return fmt.Sprintf("%x", h)
}
