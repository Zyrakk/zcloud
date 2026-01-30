# ZCloud Architecture Documentation

> **Version:** 1.5.0
> **Last Updated:** January 2025
> **Maintainer:** Zyrak

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Components](#components)
4. [Data Flow](#data-flow)
5. [Security Architecture](#security-architecture)
6. [Database Schema](#database-schema)
7. [API Endpoints](#api-endpoints)
8. [Client Architecture](#client-architecture)
9. [Server Architecture](#server-architecture)
10. [Design Patterns](#design-patterns)
11. [Configuration Management](#configuration-management)
12. [Deployment Architecture](#deployment-architecture)
13. [Future Enhancements](#future-enhancements)

---

## Overview

ZCloud is a secure remote management system for k3s Kubernetes clusters that enables administration from any Linux device without VPN or manual kubeconfig configuration.

### Key Design Principles

- **Security First**: Multi-layer authentication (Ed25519 + TOTP + JWT)
- **Zero Trust**: Device-based authorization with approval workflow
- **Simplicity**: Single binary deployment for both client and server
- **Portability**: Cross-platform support (Linux AMD64/ARM64)
- **Stateless Client**: All state stored in server; client holds minimal config

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           HIGH-LEVEL ARCHITECTURE                         │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐                                                     ┌──────────────┐
│   CLIENT     │                                                     │   SERVER     │
│   zcloud     │                                                     │ zcloud-server │
│   CLI        │                                                     │  API + DB    │
└──────────────┘                                                     └──────────────┘
       │                                                                      │
       │  1. Registration (Ed25519 PubKey + Device Info)                       │
       ├─────────────────────────────────────────────────────────────────────────────>│
       │                                                                      │
       │  2. Approval (Manual by Admin)                                        │
       │  <────────────────────────────────────────────────────────────────────────────│
       │                                                                      │
       │  3. TOTP Setup (Secret Exchange)                                       │
       │  <────────────────────────────────────────────────────────────────────────────│
       │                                                                      │
       │  4. Daily Login (Signature + TOTP)                                     │
       ├─────────────────────────────────────────────────────────────────────────────>│
       │                                                                      │
       │  5. JWT Token (12h TTL)                                                │
       │  <────────────────────────────────────────────────────────────────────────────│
       │                                                                      │
       │  6. API Requests (Authorized by JWT)                                   │
       ├─────────────────────────────────────────────────────────────────────────────>│
       │                                                                      │
       │  7. k8s Operations (Proxied)                                         │
       │  <────────────────────────────────────────────────────────────────────────────│
```

---

## Components

### Client Components (`zcloud` CLI)

```
zcloud/
├── cmd/zcloud/
│   └── main.go                    # CLI entry point (Cobra commands)
├── internal/client/
│   ├── auth.go                     # Authentication logic
│   ├── config.go                   # Configuration management
│   ├── http.go                     # HTTP client for API calls
│   ├── files.go                    # File transfer client
│   ├── ssh.go                      # SSH WebSocket client
│   ├── portforward.go              # Port forwarding client
│   └── kubeconfig.go              # Kubeconfig generation
└── shared/
    └── crypto/
        ├── keys.go                  # Ed25519 key management
        └── totp.go                  # TOTP generation/validation
```

### Server Components (`zcloud-server` API)

```
zcloud-server/
├── cmd/zcloud-server/
│   └── main.go                    # Server entry point
├── internal/server/
│   ├── api/
│   │   ├── handlers.go             # HTTP request handlers
│   │   ├── k8s_proxy.go           # Kubernetes API proxy
│   │   ├── ssh.go                  # SSH WebSocket handler
│   │   ├── portforward.go         # Port forwarding WebSocket
│   │   └── files.go                # File transfer handlers
│   ├── db/
│   │   └── database.go            # SQLite database operations
│   └── middleware/
│       └── auth.go                 # JWT auth + rate limiting
├── internal/shared/
│   ├── protocol/
│   │   └── types.go               # Shared data structures
│   └── crypto/
│       ├── keys.go                  # Shared crypto functions
│       └── totp.go                  # Shared TOTP functions
└── storage/
    └── zcloud.db                  # SQLite database
```

---

## Data Flow

### Device Registration Flow

```
1. CLIENT: Generate Ed25519 keypair
   ├─ Private key saved locally (~/.zcloud/device.key)
   └─ Public key sent to server

2. SERVER: Create device record
   ├─ Device ID: SHA256(public_key)[:12]
   ├─ Status: "pending" (if approval required)
   └─ Store in devices table

3. ADMIN: Approve device (server-side)
   ├─ Update status to "approved"
   ├─ Generate TOTP secret
   └─ Store TOTP secret in devices table

4. CLIENT: Complete registration
   ├─ Fetch TOTP secret
   ├─ Configure authenticator app
   └─ Save configuration
```

### Authentication Flow

```
1. CLIENT: Prepare login request
   ├─ Get current timestamp
   ├─ Sign timestamp with private key
   ├─ Get TOTP code from user
   └─ Send: {device_id, timestamp, signature, totp_code}

2. SERVER: Validate login
   ├─ Verify signature with public key
   ├─ Validate timestamp (±5 minutes window)
   ├─ Validate TOTP code
   ├─ Check device status == "approved"
   └─ Generate JWT token

3. SERVER: Issue JWT
   ├─ Claims: {device_id, device_name, is_admin}
   ├─ Expires: current_time + 12h
   ├─ Sign with JWT secret
   └─ Store session in database

4. CLIENT: Receive and store JWT
   ├─ Save to ~/.zcloud/config.yaml
   ├─ Generate kubeconfig with token
   └─ Ready for API calls
```

### API Request Flow

```
1. CLIENT: Make authenticated request
   ├─ Add header: Authorization: Bearer <jwt_token>
   ├─ Add header: X-Device-ID: <device_id>
   └─ Send to server

2. SERVER: Process request
   ├─ Rate limiter check (by IP)
   ├─ JWT validation
   │  ├─ Verify signature
   │  ├─ Check expiration
   │  └─ Check revoked tokens
   ├─ Extract device_id from claims
   └─ Route to handler

3. HANDLER: Execute operation
   ├─ Perform k8s operation
   ├─ Return response
   └─ Update device last_access
```

---

## Security Architecture

### Security Layers (Defense in Depth)

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: TLS 1.3                                        │
│ - Encrypts all traffic between client and server              │
│ - Prevents MITM attacks                                    │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2: Ed25519 Device Keys                               │
│ - Uniquely identifies each device                            │
│ - Private key never leaves device                             │
│ - Prevents device impersonation                              │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3: TOTP 2FA                                         │
│ - Requires possession of TOTP secret                         │
│ - Time-based (30-second windows)                             │
│ - Prevents stolen credentials misuse                         │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4: JWT Tokens                                        │
│ - Short-lived (12h TTL)                                    │
│ - Encoded claims (device_id, is_admin)                       │
│ - Revocable on logout/device revocation                      │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│ Layer 5: Rate Limiting                                    │
│ - Prevents brute force attacks                             │
│ - 100 requests/minute per IP                               │
│ - Thread-safe implementation                               │
└─────────────────────────────────────────────────────────────────┘
```

### Token Revocation System

```go
// Revocation flow:
1. User executes: zcloud stop
2. Client sends logout request with JWT
3. Server:
   - Extracts token from Authorization header
   - Hashes token (SHA256)
   - Inserts hash into revoked_tokens table
   - Deletes device sessions
4. Future requests:
   - Server checks if token hash exists in revoked_tokens
   - If revoked, returns 401 Unauthorized
   - Automatic cleanup of expired revoked entries
```

---

## Database Schema

### Tables

```sql
-- DEVICES: Stores registered devices
CREATE TABLE devices (
    id TEXT PRIMARY KEY,                    -- SHA256(public_key)[:12]
    name TEXT NOT NULL,                     -- Human-readable name
    public_key TEXT NOT NULL UNIQUE,        -- Ed25519 public key (base64)
    hostname TEXT,                          -- Client hostname
    os TEXT,                                -- Client OS/ARCH
    status TEXT NOT NULL DEFAULT 'pending',  -- pending/approved/revoked
    totp_secret TEXT,                       -- Base32 TOTP secret
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_access DATETIME,
    is_admin INTEGER DEFAULT 0
);

-- SESSIONS: Active JWT sessions
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,                    -- Session UUID
    device_id TEXT NOT NULL,                -- FK to devices
    token_hash TEXT NOT NULL,               -- SHA256(token)
    expires_at DATETIME NOT NULL,           -- JWT expiration
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- REVOKED_TOKENS: Blacklisted JWT tokens
CREATE TABLE revoked_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,         -- SHA256(token)
    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    reason TEXT,                            -- user_logout/device_revoked
    expires_at DATETIME NOT NULL           -- Original JWT expiration
);

-- INDEXES
CREATE INDEX idx_sessions_device ON sessions(device_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_revoked_tokens_hash ON revoked_tokens(token_hash);
CREATE INDEX idx_revoked_tokens_expires ON revoked_tokens(expires_at);
```

---

## API Endpoints

### Public Endpoints (No Authentication)

| Method | Endpoint | Description | Request | Response |
|--------|----------|-------------|---------|----------|
| POST | `/api/v1/devices/register` | Register new device | RegisterRequest | RegisterResponse |
| GET | `/api/v1/devices/status` | Get device status | Query: device_id | RegisterResponse |
| POST | `/api/v1/auth/login` | Authenticate with TOTP | LoginRequest | LoginResponse |

### Protected Endpoints (JWT Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/logout` | Invalidate current session |
| GET | `/api/v1/status/cluster` | Get cluster status and nodes |
| POST | `/api/v1/k8s/apply` | Apply Kubernetes manifests |
| ALL | `/api/v1/k8s/proxy/*` | Proxy to k8s API |
| POST | `/api/v1/ssh/exec` | Execute command on server |
| GET | `/api/v1/ssh/shell` | WebSocket: Interactive SSH shell |
| POST | `/api/v1/files/upload` | Upload file to server |
| GET | `/api/v1/files/download` | Download file from server |
| GET | `/api/v1/files/list` | List files/directories |
| DELETE | `/api/v1/files/delete` | Delete file/directory |
| GET | `/api/v1/portforward` | WebSocket: Port forwarding tunnel |

### Admin Endpoints (JWT + Admin Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/devices` | List all devices |
| POST | `/api/v1/admin/devices/:id/approve` | Approve pending device |
| POST | `/api/v1/admin/devices/:id/revoke` | Revoke device |
| GET | `/api/v1/admin/sessions` | List active sessions |

---

## Client Architecture

### Command Structure (Cobra)

```
zcloud
├── init [server_url]           # Initial setup
│   └── --complete              # After approval
├── login                       # Authenticate with TOTP
├── logout                      # Invalidate session
├── totp                        # Configure TOTP
├── start                       # Daily login with TOTP
├── stop                        # End session
├── status                      [--check-only]    # Show status
├── k [kubectl args...]          # kubectl proxy
├── apply [file...]              # Apply manifests
├── exec [command...]           # Execute remote command
├── ssh                         # Interactive shell
├── cp [src] [dst]              # File transfer
├── port-forward <host> <ports> # Port tunnel
└── admin devices                # Device management
    ├── list
    ├── approve <id>
    └── revoke <id>
```

### Client State Management

```
~/.zcloud/
├── config.yaml                  # Main configuration
│   ├── server:
│   │   ├── url: https://api.zyrak.cloud
│   │   └── insecure: false
│   ├── device:
│   │   ├── id: <device_id>
│   │   ├── name: <device_name>
│   │   ├── approved: true
│   │   └── trusted: true
│   ├── session:
│   │   ├── token: <jwt_token>
│   │   └── expires_at: <timestamp>
│   └── cluster:
│       ├── name: "zcloud-homelab"
│       └── context: "zcloud"
├── device.key                   # Ed25519 private key (base64, 0600)
├── device.pub                   # Ed25519 public key (base64)
└── kubeconfig                   # Generated k8s config
```

---

## Server Architecture

### HTTP Server Configuration

```go
server := &http.Server{
    Addr:         "0.0.0.0:443",
    Handler:      apiRouter,
    ReadTimeout:  30 * time.Second,
    WriteTimeout: 30 * time.Second,
    IdleTimeout:  120 * time.Second,
}
```

### Middleware Chain

```
Request → CORS → RateLimiter → Authenticate → RequireAdmin → Handler
           (global)  (per IP)     (JWT check)   (if needed)
```

### Background Jobs

```go
// 1. Cleanup expired sessions (every hour)
go func() {
    ticker := time.NewTicker(time.Hour)
    for range ticker.C {
        database.CleanExpiredSessions()
    }
}()

// 2. Cleanup revoked tokens (automatic in IsTokenRevoked)
//    - Runs on every token validation
//    - Removes expired entries
```

### WebSocket Handlers

```go
// SSH Shell
client --[WebSocket: /api/v1/ssh/shell]--> server
    └─双向流: stdin/stdout + resize events

// Port Forwarding
client --[WebSocket: /api/v1/portforward]--> server --[TCP]--> k8s service
    └─双向流: bidirectional data relay
```

---

## Design Patterns

### 1. Repository Pattern
**Location:** `internal/server/db/database.go`
**Usage:** Encapsulates database operations
```go
type Database struct {
    db *sql.DB
}
func (d *Database) CreateDevice(...) error { ... }
func (d *Database) GetDevice(...) (*DeviceInfo, error) { ... }
```

### 2. Middleware Pattern
**Location:** `internal/server/middleware/auth.go`
**Usage:** Chainable HTTP middleware
```go
handler := auth.Authenticate(
    rateLimiter.Limit(
        cors.Wrap(http.HandlerFunc(handler)),
    ),
)
```

### 3. Builder Pattern
**Location:** `internal/server/api/`
**Usage:** Building responses
```go
resp := &protocol.LoginResponse{
    Token:     token,
    ExpiresAt: expiresAt,
    Message:   "Login successful",
}
```

### 4. Factory Pattern
**Location:** `internal/shared/crypto/keys.go`
**Usage:** Creating cryptographic objects
```go
func GenerateKeyPair() (*KeyPair, error) { ... }
func NewAuthMiddleware(jwtSecret string) *AuthMiddleware { ... }
```

### 5. Strategy Pattern
**Location:** `internal/client/`
**Usage:** Different authentication strategies
```go
type Auth struct {
    Init() error
    Login() error
    Logout() error
}
```

---

## Configuration Management

### Server Configuration (`/opt/zcloud-server/config.yaml`)

```yaml
server:
  host: 0.0.0.0
  port: 443
  domain: api.zyrak.cloud

tls:
  cert: /opt/zcloud-server/certs/fullchain.pem
  key: /opt/zcloud-server/certs/privkey.pem
  auto_renew: true

auth:
  jwt_secret_file: /opt/zcloud-server/data/jwt.secret
  session_ttl: 12h
  totp_issuer: "ZCloud"
  require_approval: true

kubernetes:
  kubeconfig: /etc/rancher/k3s/k3s.yaml
  coredns_ip: 10.43.0.10:53          # Configurable CoreDNS IP

storage:
  database: /opt/zcloud-server/data/zcloud.db
```

### Client Configuration (`~/.zcloud/config.yaml`)

```yaml
server:
  url: https://api.zyrak.cloud
  insecure: false

device:
  id: a1b2c3d4e5f6
  name: my-laptop
  approved: true
  trusted: true

session:
  token: eyJhbGc...
  expires_at: 2025-01-30T12:00:00Z

cluster:
  name: "zcloud-homelab"
  context: "zcloud"
```

---

## Deployment Architecture

### Server Deployment

```
/opt/zcloud-server/
├── zcloud-server                    # Binary
├── config.yaml                       # Configuration
├── data/
│   ├── zcloud.db                     # SQLite database
│   └── jwt.secret                    # JWT signing secret
└── certs/
    ├── fullchain.pem                  # TLS certificate
    └── privkey.pem                   # TLS private key

Systemd Service:
  ├── zcloud-server.service
  └── Managed by systemctl
      ├── Start: systemctl start zcloud-server
      ├── Stop: systemctl stop zcloud-server
      └── Status: systemctl status zcloud-server
```

### Client Deployment

```
/usr/local/bin/
└── zcloud                            # Binary (any Linux)

~/.zcloud/
├── config.yaml
├── device.key
├── device.pub
└── kubeconfig                         # Generated on login
```

### Network Flow

```
Client (anywhere)
    |
    | HTTPS (TLS 1.3)
    | Domain: api.zyrak.cloud:443
    |
    V
Server (N150 / homelab)
    |
    | HTTP handlers
    |
    V
k3s Cluster (4 nodes via VPN)
    ├── Node 1: k3s-master
    ├── Node 2: k3s-worker-1
    ├── Node 3: k3s-worker-2
    └── Node 4: k3s-worker-3
```

---

## Future Enhancements

### Planned Features

1. **Multi-Cluster Support**
   - Add `cluster_id` to devices table
   - Support managing multiple k3s clusters
   - Cluster selection in CLI

2. **Webhook Notifications**
   - Telegram integration for device approvals
   - Email notifications for security events
   - Webhook configuration in config.yaml

3. **Advanced Session Management**
   - Session listing from client
   - Remote session revocation
   - Concurrent session limits

4. **Enhanced Port Forwarding**
   - UDP support
   - Multi-port forwarding
   - SOCKS proxy support

5. **Metrics & Observability**
   - Prometheus metrics endpoint
   - Structured logging (JSON)
   - Distributed tracing

6. **Database Migrations**
   - Versioned schema migrations
   - Rollback support
   - Automated upgrades

7. **API Versioning**
   - `/api/v1/` (current)
   - `/api/v2/` (future)
   - Backward compatibility layer

### Technical Debt

1. **Testing**
   - Currently: 64 unit tests
   - Goal: Add integration tests
   - Goal: E2E tests with test k3s cluster

2. **Documentation**
   - API documentation (OpenAPI/Swagger)
   - Contributing guidelines
   - Architecture decision records (ADRs)

3. **Error Handling**
   - Standardize error responses
   - Better error messages
   - Error codes reference

4. **Performance**
   - Connection pooling for HTTP client
   - Caching for k8s API responses
   - Optimize database queries

5. **Security**
   - Content Security Policy headers
   - HSTS headers
   - Request signing validation

---

## Technical Decisions

### Why Ed25519 over RSA/ECDSA?
- **Smaller keys**: 32-byte public key vs 256+ bytes for RSA
- **Faster operations**: Signature verification is ~10x faster than RSA
- **Modern crypto**: No known vulnerabilities
- **Deterministic signatures**: Same input produces same signature

### Why SQLite over PostgreSQL/MySQL?
- **Zero configuration**: Single file database
- **Easy backup**: Just copy the `.db` file
- **Sufficient scale**: Handles homelab traffic easily
- **Embedded**: No external database service needed

### Why WebSockets for SSH/Port Forwarding?
- **Bidirectional**: Full-duplex communication
- **Low latency**: Real-time interactive shell
- **HTTP/2 compatible**: Works through standard proxies
- **Authentication**: Reuses JWT auth mechanism

### Why JWT tokens over session cookies?
- **Stateless**: No server-side session storage needed
- **Cross-device**: Works with CLI and potential web UI
- **Mobile-friendly**: Standard HTTP header auth
- **Revocable**: With blacklist system

### Why TOTP over SMS/email?
- **Offline capable**: No network needed to generate codes
- **No delivery issues**: Codes generated locally
- **Standard**: Works with Google Authenticator, Authy, etc.
- **Secure**: Time-based prevents reuse

---

## Contributing Guidelines

### Code Style

- **Language**: Go 1.22+
- **Formatting**: `gofmt -s -w`
- **Linting**: `go vet ./...`
- **Testing**: `go test -v ./...`
- **Comments**: Spanish (as per current codebase)

### Project Structure

```
Add new features:
1. Add protocol types to: internal/shared/protocol/types.go
2. Implement client in: internal/client/
3. Implement server in: internal/server/api/
4. Add database methods in: internal/server/db/database.go
5. Update tests for new functionality
6. Update documentation
```

### Testing Guidelines

```go
// Test naming: Test[Function][Scenario][ExpectedResult]
func TestCreateDevice_WithValidData_ReturnsNoError(t *testing.T) {
    // Arrange
    db := setupTestDB(t)
    device := &protocol.DeviceInfo{...}

    // Act
    err := db.CreateDevice(device, "totp-secret")

    // Assert
    if err != nil {
        t.Errorf("Expected no error, got %v", err)
    }
}
```

---

## References

- [Cobra Documentation](https://github.com/spf13/cobra)
- [Gorilla WebSocket](https://github.com/gorilla/websocket)
- [go-jwt/jwt](https://github.com/golang-jwt/jwt)
- [Modernc SQLite](https://gitlab.com/cznic/sqlite)
- [Ed25519 in Go](https://pkg.go.dev/crypto/ed25519)

---

**Last Modified:** January 30, 2025
**Document Version:** 1.0
