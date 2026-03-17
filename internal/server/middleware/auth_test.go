package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zyrak/zcloud/internal/server/middleware"
)

func TestNewAuthMiddleware(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	if am == nil {
		t.Fatal("AuthMiddleware is nil")
	}
}

func TestGenerateToken(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	token, expiresAt, err := am.GenerateToken("device-id", "Test Device", false, 12*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Error("Token is empty")
	}

	if expiresAt.IsZero() {
		t.Error("ExpiresAt is zero")
	}

	if time.Until(expiresAt) > 12*time.Hour+time.Minute || time.Until(expiresAt) < 11*time.Hour {
		t.Errorf("ExpiresAt not within expected range: %v", expiresAt)
	}
}

func TestGenerateTokenAdmin(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	token, _, err := am.GenerateToken("device-id", "Test Device", true, 12*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate admin token: %v", err)
	}

	if token == "" {
		t.Error("Admin token is empty")
	}

	claims, err := am.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate admin token: %v", err)
	}

	if !claims.IsAdmin {
		t.Error("Admin token should have IsAdmin=true")
	}
}

func TestValidateToken(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	token, _, err := am.GenerateToken("device-id", "Test Device", false, 12*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	claims, err := am.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.DeviceID != "device-id" {
		t.Errorf("Expected DeviceID device-id, got %s", claims.DeviceID)
	}

	if claims.DeviceName != "Test Device" {
		t.Errorf("Expected DeviceName Test Device, got %s", claims.DeviceName)
	}

	if claims.IsAdmin {
		t.Error("Token should not be admin")
	}
}

func TestValidateTokenInvalid(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	_, err := am.ValidateToken("invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
}

func TestValidateTokenWrongSecret(t *testing.T) {
	am1 := middleware.NewAuthMiddleware("secret-1")
	defer am1.Close()
	token, _, err := am1.GenerateToken("device-id", "Test Device", false, 12*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	am2 := middleware.NewAuthMiddleware("secret-2")
	defer am2.Close()
	_, err = am2.ValidateToken(token)
	if err == nil {
		t.Error("Expected error for token with wrong secret")
	}
}

func TestAuthenticateMiddleware(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	token, _, err := am.GenerateToken("device-id", "Test Device", false, 12*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deviceID := middleware.GetDeviceID(r)
		if deviceID != "device-id" {
			t.Errorf("Expected device-id, got %s", deviceID)
		}
		w.WriteHeader(http.StatusOK)
	})

	authenticatedHandler := am.Authenticate(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	authenticatedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuthenticateMiddlewareNoToken(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authenticatedHandler := am.Authenticate(handler)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	authenticatedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestAuthenticateMiddlewareInvalidToken(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authenticatedHandler := am.Authenticate(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	authenticatedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestAuthenticateMiddlewareMalformedHeader(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authenticatedHandler := am.Authenticate(handler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "InvalidFormat token")
	w := httptest.NewRecorder()

	authenticatedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestRequireAdminMiddleware(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	token, _, err := am.GenerateToken("device-id", "Test Device", true, 12*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate admin token: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	adminHandler := am.RequireAdmin(handler)
	authenticatedHandler := am.Authenticate(adminHandler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	authenticatedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for admin, got %d", w.Code)
	}
}

func TestRequireAdminMiddlewareNonAdmin(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	token, _, err := am.GenerateToken("device-id", "Test Device", false, 12*time.Hour)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	adminHandler := am.RequireAdmin(handler)
	authenticatedHandler := am.Authenticate(adminHandler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	authenticatedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for non-admin, got %d", w.Code)
	}
}

func TestGetDeviceID(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	ctx := req.Context()
	ctx = context.WithValue(ctx, middleware.DeviceIDKey, "test-device-id")

	req = req.WithContext(ctx)

	deviceID := middleware.GetDeviceID(req)
	if deviceID != "test-device-id" {
		t.Errorf("Expected test-device-id, got %s", deviceID)
	}
}

func TestGetIsAdmin(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	ctx := req.Context()
	ctx = context.WithValue(ctx, middleware.IsAdminKey, true)

	req = req.WithContext(ctx)

	isAdmin := middleware.GetIsAdmin(req)
	if !isAdmin {
		t.Error("Expected isAdmin to be true")
	}
}

func TestTokenExpiration(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	token, _, err := am.GenerateToken("device-id", "Test Device", false, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	_, err = am.ValidateToken(token)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestConcurrentTokenGeneration(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	var wg sync.WaitGroup
	tokens := make([]string, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token, _, err := am.GenerateToken("device-id", "Test Device", false, 12*time.Hour)
			if err != nil {
				t.Errorf("Failed to generate token %d: %v", idx, err)
				return
			}
			tokens[idx] = token
		}(i)
	}

	wg.Wait()

	for i, token := range tokens {
		if token == "" {
			t.Errorf("Token %d is empty", i)
		}

		claims, err := am.ValidateToken(token)
		if err != nil {
			t.Errorf("Failed to validate token %d: %v", i, err)
		}

		if claims.DeviceID != "device-id" {
			t.Errorf("Token %d has wrong device ID", i)
		}
	}
}

// --- New security tests ---

func TestValidateTokenAlgorithmConfusion(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()

	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"device_id":   "test-device",
		"device_name": "test",
		"iss":         "zcloud",
		"exp":         time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to create none-alg token: %v", err)
	}

	_, err = am.ValidateToken(tokenString)
	if err == nil {
		t.Error("expected error for none-algorithm token, got nil")
	}
}

type mockDBError struct{}

func (m *mockDBError) IsTokenRevoked(tokenHash string) (bool, error) {
	return false, fmt.Errorf("database unavailable")
}

type mockDBRevoked struct{}

func (m *mockDBRevoked) IsTokenRevoked(tokenHash string) (bool, error) {
	return true, nil
}

func TestValidateTokenRevocationDBError(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()
	am.SetDatabase(&mockDBError{})

	tokenStr, _, err := am.GenerateToken("device-1", "test", false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = am.ValidateToken(tokenStr)
	if err == nil {
		t.Error("expected error when DB revocation check fails, got nil (fail-open)")
	}
}

func TestValidateTokenRevoked(t *testing.T) {
	am := middleware.NewAuthMiddleware("test-secret")
	defer am.Close()
	am.SetDatabase(&mockDBRevoked{})

	tokenStr, _, err := am.GenerateToken("device-1", "test", false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = am.ValidateToken(tokenStr)
	if err == nil {
		t.Error("expected error for revoked token, got nil")
	}
}
