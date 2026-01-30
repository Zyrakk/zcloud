package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	DeviceIDKey contextKey = "device_id"
	IsAdminKey  contextKey = "is_admin"
)

// JWTClaims representa los claims del JWT
type JWTClaims struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	IsAdmin    bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

// AuthMiddleware middleware de autenticación JWT
type AuthMiddleware struct {
	jwtSecret []byte
	db        interface {
		IsTokenRevoked(tokenHash string) (bool, error)
	}
}

// NewAuthMiddleware crea un nuevo middleware de autenticación
func NewAuthMiddleware(jwtSecret string) *AuthMiddleware {
	return &AuthMiddleware{
		jwtSecret: []byte(jwtSecret),
		db:        nil,
	}
}

// SetDatabase sets the database for token revocation checking
func (m *AuthMiddleware) SetDatabase(db interface {
	IsTokenRevoked(tokenHash string) (bool, error)
}) {
	m.db = db
}

// GenerateToken genera un nuevo JWT
func (m *AuthMiddleware) GenerateToken(deviceID, deviceName string, isAdmin bool, duration time.Duration) (string, time.Time, error) {
	expiresAt := time.Now().Add(duration)

	claims := &JWTClaims{
		DeviceID:   deviceID,
		DeviceName: deviceName,
		IsAdmin:    isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "zcloud",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

// ValidateToken valida un JWT y devuelve los claims
func (m *AuthMiddleware) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return m.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		// Check if token is revoked
		if m.db != nil {
			tokenHash := hashToken(tokenString)
			revoked, err := m.db.IsTokenRevoked(tokenHash)
			if err != nil {
				return nil, fmt.Errorf("failed to check token revocation: %w", err)
			}
			if revoked {
				return nil, jwt.ErrTokenInvalidClaims
			}
		}
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}

// hashToken genera un hash SHA256 del token para almacenamiento seguro
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// Authenticate middleware que verifica el JWT
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, `{"error": "invalid authorization header"}`, http.StatusUnauthorized)
			return
		}

		claims, err := m.ValidateToken(parts[1])
		if err != nil {
			http.Error(w, `{"error": "invalid token"}`, http.StatusUnauthorized)
			return
		}

		// Añadir información al contexto
		ctx := context.WithValue(r.Context(), DeviceIDKey, claims.DeviceID)
		ctx = context.WithValue(ctx, IsAdminKey, claims.IsAdmin)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin middleware que verifica que el usuario es admin
func (m *AuthMiddleware) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAdmin, ok := r.Context().Value(IsAdminKey).(bool)
		if !ok || !isAdmin {
			http.Error(w, `{"error": "admin access required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GetDeviceID obtiene el device ID del contexto
func GetDeviceID(r *http.Request) string {
	deviceID, _ := r.Context().Value(DeviceIDKey).(string)
	return deviceID
}

// GetIsAdmin obtiene si el usuario es admin del contexto
func GetIsAdmin(r *http.Request) bool {
	isAdmin, _ := r.Context().Value(IsAdminKey).(bool)
	return isAdmin
}

// RateLimiter middleware simple de rate limiting
type RateLimiter struct {
	requests map[string][]time.Time
	limit    int
	window   time.Duration
	mu       sync.RWMutex
}

// NewRateLimiter crea un nuevo rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Limit middleware de rate limiting
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		now := time.Now()
		windowStart := now.Add(-rl.window)

		// Lock for write operations
		rl.mu.Lock()

		// Limpiar requests antiguos
		var validRequests []time.Time
		for _, t := range rl.requests[ip] {
			if t.After(windowStart) {
				validRequests = append(validRequests, t)
			}
		}
		rl.requests[ip] = validRequests

		// Verificar límite
		if len(rl.requests[ip]) >= rl.limit {
			rl.mu.Unlock()
			http.Error(w, `{"error": "rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}

		// Registrar request
		rl.requests[ip] = append(rl.requests[ip], now)

		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// CORS middleware para CORS
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Device-ID")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Logger middleware para logging
func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)

		// Log simple
		deviceID := r.Header.Get("X-Device-ID")
		if deviceID == "" {
			deviceID = "-"
		} else if len(deviceID) > 8 {
			deviceID = deviceID[:8]
		}

		// Formato: [timestamp] METHOD /path device_id duration
		// log.Printf("[%s] %s %s %s %v", time.Now().Format("15:04:05"), r.Method, r.URL.Path, deviceID, duration)
		_ = duration // Evitar warning si no se usa
	})
}
