package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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

// tokenCacheEntry represents a cached token validation result
type tokenCacheEntry struct {
	claims    *JWTClaims
	expiresAt time.Time
}

// AuthMiddleware middleware de autenticación JWT
type AuthMiddleware struct {
	jwtSecret []byte
	db        interface {
		IsTokenRevoked(tokenHash string) (bool, error)
	}
	// Token validation cache to reduce database queries under high concurrency
	tokenCache   map[string]*tokenCacheEntry
	tokenCacheMu sync.RWMutex
	cacheTTL     time.Duration
	done         chan struct{}
	closeOnce    sync.Once
}

// NewAuthMiddleware crea un nuevo middleware de autenticación
func NewAuthMiddleware(jwtSecret string) *AuthMiddleware {
	m := &AuthMiddleware{
		jwtSecret:  []byte(jwtSecret),
		db:         nil,
		tokenCache: make(map[string]*tokenCacheEntry),
		cacheTTL:   30 * time.Second, // Cache validated tokens for 30 seconds
		done:       make(chan struct{}),
	}

	// Start background cleanup goroutine
	go m.cleanupExpiredCache()

	return m
}

// Close stops the background cleanup goroutine. Safe to call multiple times.
func (m *AuthMiddleware) Close() {
	m.closeOnce.Do(func() { close(m.done) })
}

// cleanupExpiredCache periodically removes expired entries from the token cache
func (m *AuthMiddleware) cleanupExpiredCache() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			m.tokenCacheMu.Lock()
			now := time.Now()
			for k, v := range m.tokenCache {
				if now.After(v.expiresAt) {
					delete(m.tokenCache, k)
				}
			}
			m.tokenCacheMu.Unlock()
		}
	}
}

// SetDatabase sets the database for token revocation checks.
// Must be called before the server starts accepting requests.
func (m *AuthMiddleware) SetDatabase(db interface {
	IsTokenRevoked(tokenHash string) (bool, error)
}) {
	m.db = db
}

// InvalidateToken removes a token from the cache (called on logout/revocation)
func (m *AuthMiddleware) InvalidateToken(tokenString string) {
	tokenHash := hashToken(tokenString)
	m.tokenCacheMu.Lock()
	delete(m.tokenCache, tokenHash)
	m.tokenCacheMu.Unlock()
}

// InvalidateDevice removes all cached tokens for a given device from the cache.
func (m *AuthMiddleware) InvalidateDevice(deviceID string) {
	m.tokenCacheMu.Lock()
	defer m.tokenCacheMu.Unlock()
	for k, v := range m.tokenCache {
		if v.claims.DeviceID == deviceID {
			delete(m.tokenCache, k)
		}
	}
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
// Uses an in-memory cache to reduce database queries under high concurrency
func (m *AuthMiddleware) ValidateToken(tokenString string) (*JWTClaims, error) {
	tokenHash := hashToken(tokenString)

	// Check cache first (fast path for concurrent requests)
	m.tokenCacheMu.RLock()
	if entry, ok := m.tokenCache[tokenHash]; ok && time.Now().Before(entry.expiresAt) {
		m.tokenCacheMu.RUnlock()
		return entry.claims, nil
	}
	m.tokenCacheMu.RUnlock()

	// Cache miss - parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		// Check if token is revoked (only on cache miss)
		if m.db != nil {
			revoked, err := m.db.IsTokenRevoked(tokenHash)
			if err != nil {
				return nil, fmt.Errorf("revocation check failed: %w", err)
			}
			if revoked {
				return nil, jwt.ErrTokenInvalidClaims
			}
		}

		// Cache the validated token
		m.tokenCacheMu.Lock()
		m.tokenCache[tokenHash] = &tokenCacheEntry{
			claims:    claims,
			expiresAt: time.Now().Add(m.cacheTTL),
		}
		m.tokenCacheMu.Unlock()

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
	requests   map[string][]time.Time
	limit      int
	window     time.Duration
	mu         sync.RWMutex
	cleaning   atomic.Bool
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
		ip := clientIP(r)

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

		// Trigger cleanup when map grows large to prevent unbounded memory growth.
		// Use atomic flag to ensure at most one cleanup goroutine runs at a time.
		if len(rl.requests) > 10000 && rl.cleaning.CompareAndSwap(false, true) {
			go func() {
				defer rl.cleaning.Store(false)
				rl.cleanup()
			}()
		}

		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// cleanup removes stale IP entries from the rate limiter map.
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, times := range rl.requests {
		valid := times[:0]
		for _, t := range times {
			if now.Sub(t) <= rl.window {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

func clientIP(r *http.Request) string {
	// Default: RemoteAddr without port.
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && h != "" {
		host = h
	}

	// If running behind a local reverse proxy, RemoteAddr will be loopback.
	// In that case it's safe/useful to honor X-Forwarded-For for rate limiting.
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			// Take the left-most (original client) IP.
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				candidate := strings.TrimSpace(parts[0])
				if net.ParseIP(candidate) != nil {
					return candidate
				}
			}
		}
	}

	return host
}

// CORSWithOrigin returns a CORS middleware that sets the given allowed origin.
// If allowedOrigin is empty, it defaults to "*".
func CORSWithOrigin(allowedOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := allowedOrigin
			if origin == "" {
				origin = "*"
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Device-ID")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Deprecated: Use CORSWithOrigin with an explicit origin instead.
func CORS(next http.Handler) http.Handler {
	return CORSWithOrigin("")(next)
}

// SecurityHeaders middleware sets security-related HTTP headers
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Content Security Policy
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")

		// X-Frame-Options: prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// X-Content-Type-Options: prevent MIME-sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// X-XSS-Protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Strict-Transport-Security (only on HTTPS)
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Referrer-Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions-Policy (Feature Policy)
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// Cache-Control for endpoints that shouldn't be cached
		if r.URL.Path == "/api/v1/auth/login" || r.URL.Path == "/api/v1/devices/register" {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
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
		log.Printf("[%s] %s %s %s %v", time.Now().Format("15:04:05"), r.Method, r.URL.Path, deviceID, duration)
		_ = duration // Evitar warning si no se usa
	})
}

// AuditLogger logs important security events
type AuditLogger struct {
	logLevel string
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logLevel string) *AuditLogger {
	return &AuditLogger{
		logLevel: logLevel,
	}
}

// LogAudit logs an audit event
func (al *AuditLogger) LogAudit(event, deviceID, details string) {
	if al.logLevel == "disabled" {
		return
	}
	logEntry := fmt.Sprintf("AUDIT [%s] device=%s %s", event, deviceID, details)
	log.Print(logEntry)
}
