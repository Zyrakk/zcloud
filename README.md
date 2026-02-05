# ZCloud CLI

Remote management system for k3s clusters. It lets you connect to and operate your homelab securely from anywhere.

## 🏗️ Architecture

```
┌─────────────────────────────┐          ┌─────────────────────────────┐
│  CLIENT (any Linux)         │          │  SERVER (N150)              │
│                             │          │                             │
│  zcloud CLI                 │  HTTPS   │  zcloud-server              │
│  - Device keys (Ed25519)    │◄────────►│  - REST API                 │
│  - TOTP (per user)          │   :443   │  - JWT sessions             │
│  - kubectl proxy            │          │  - kubectl proxy            │
│                             │          │  - Device management        │
└─────────────────────────────┘          └──────────┬──────────────────┘
                                                    │
                                                    ▼
                                         ┌─────────────────────────────┐
                                         │  k3s cluster                │
                                         │  (4 nodes via VPN)          │
                                         └─────────────────────────────┘
```

## 🔐 Security

| Layer | Mechanism | Purpose |
|------|-----------|---------|
| 1 | TLS 1.3 | Encryption in transit |
| 2 | Device Key (Ed25519) | Identifies the device |
| 3 | TOTP | Proves the user is present |
| 4 | JWT (12h TTL) | Temporary session |
| 5 | Token Revocation | Immediate session invalidation |
| 6 | Security Headers | XSS/clickjacking mitigation, etc. |
| 7 | Rate limiting | Abuse prevention (selective) |
| 8 | Audit Logging | Security trail |

Notes:
- The **TOTP secret is not exposed** via public endpoints. The user receives it **exactly once** using a one-time *Enrollment code* plus a device-key signature.
- Rate limiting is applied per **IP** (not `IP:port`). If the server is behind a local reverse proxy (loopback), `X-Forwarded-For` is used to rate-limit per client.
- The **Kubernetes API proxy** (`/api/v1/k8s/proxy/*`) is **excluded from rate limiting** to support tools like Helm that make many parallel requests. Authentication is still required.

### Token Revocation

ZCloud includes a JWT token revocation system to invalidate sessions immediately:

- **Explicit logout**: tokens are revoked when running `zcloud logout`
- **Device revocation**: all tokens for a device are revoked when the device is revoked
- **Automatic blacklist**: revoked tokens are blacklisted
- **Automatic cleanup**: expired revoked tokens are removed

This prevents token reuse after logout/revocation and improves overall security.

### Security Headers

ZCloud sets HTTP security headers to protect against common attacks:

- **Content-Security-Policy (CSP)**: mitigates XSS
- **X-Frame-Options: DENY**: mitigates clickjacking
- **X-Content-Type-Options: nosniff**: mitigates MIME sniffing
- **X-XSS-Protection**: additional XSS protection
- **Strict-Transport-Security (HSTS)**: mitigates HTTPS downgrade
- **Referrer-Policy**: referrer privacy
- **Permissions-Policy**: browser feature control

### TLS Verification

ZCloud validates TLS certificates correctly when talking to the k3s API:

- **CA verification**: uses valid CA certs instead of `InsecureSkipVerify`
- **Custom CA support**: configurable via `kubernetes.ca_cert`
- **Autodetection**: extracts CA from kubeconfig if not explicitly set
- **Security**: mitigates MITM for k3s communication

### Audit Logging

ZCloud logs important security events for auditing:

- **Events**: device registration, login, logout, approval, revocation
- **Configurable**: log level (debug/info/warn/error/disabled)
- **Timestamped**: every entry includes a precise timestamp
- **Details**: includes device ID, IP, and extra metadata

Example logs:
```
[2025-01-30 14:30:00] AUDIT: device_registered device=a1b2c3d4e5f6 details=name=my-laptop
[2025-01-30 14:30:15] AUDIT: login_success device=a1b2c3d4e5f6 details=ip=192.168.1.100
[2025-01-30 14:45:22] AUDIT: logout device=a1b2c3d4e5f6 details=ip=192.168.1.100
```

## 📦 Installation

### Server (N150)

```bash
# Option 1: installer script
curl -fsSL https://api.zyrak.cloud/install-server.sh | sudo bash

# Option 2: manual
git clone https://github.com/zyrak/zcloud
cd zcloud
make build-server
sudo make install-server
sudo /opt/zcloud-server/zcloud-server --init
```

### Client (any Linux)

```bash
# Option 1: installer script
curl -fsSL https://api.zyrak.cloud/install.sh | bash

# Option 2: manual
git clone https://github.com/zyrak/zcloud
cd zcloud
make build-client
sudo make install-client
```

## 🚀 Usage

### First-time setup (client)

```bash
# 1. Initialize client (you'll be asked for a user/persona name)
zcloud init https://api.zyrak.cloud

# 2. On the SERVER, approve the device and assign it to a user/persona
#    (so multiple devices can share the same TOTP)
zcloud-server admin devices approve <device_id> --user stefan
# This prints an "Enrollment code" (one-time, expires in ~10 minutes)

# 3. On the client, confirm approval
zcloud init --complete

# 4. Configure TOTP (only once per user/persona)
zcloud totp ABCD-EFGH-IJKL

# 5. Configure shell (add to ~/.zshrc or ~/.bashrc)
echo 'export KUBECONFIG="$HOME/.zcloud/kubeconfig:$KUBECONFIG"' >> ~/.zshrc
source ~/.zshrc
```

### TOTP Per User (1 code for all your devices)

- TOTP is **per user/persona**, not per device.
- When you approve a device, you assign it to a user with `--user <name>`.
- The server generates a one-time **Enrollment code** so the user can fetch the TOTP secret **exactly once** in their terminal.
- The client prints an ASCII QR code (plus the manual secret) during `zcloud totp`.
- Once configured in your authenticator app (Google Authenticator, Aegis, etc.), you can approve more devices with the same `--user` and they can use `zcloud login` with the same TOTP.

To rotate/reset a user's TOTP:

```bash
zcloud-server admin users rotate <user_name> --device <device_id>
# This prints a new Enrollment code; the user applies it with:
zcloud totp ABCD-EFGH-IJKL
```

### Daily use

```bash
# Start a session (once per day, prompts for TOTP)
zcloud login

# Now you can use kubectl directly!
kubectl get pods -A
kubectl get nodes
kubectl describe pod <pod>

# The internal proxy also works
zcloud k get pods -A

# Cluster/session status
zcloud status

# Apply manifests
zcloud apply ./deployment.yaml
zcloud apply ./k8s/

# Logout (optional)
zcloud logout
```

> 💡 **Powerlevel10k**: after `zcloud login`, your prompt will show `☸ zcloud-homelab`

### Administration (from a client with an admin session)

```bash
# List devices
zcloud admin devices list

# Approve a pending device (and assign it to a user/persona for shared TOTP)
zcloud admin devices approve <device_id> --user stefan

# Revoke a device
zcloud admin devices revoke <device_id>
```

### 🔄 Binary updates

When new versions are available, update like this:

**Client (any Linux):**
```bash
cd ~/Git_Repos/zcloud  # Or wherever you cloned it
git pull
make build-client
sudo cp dist/zcloud-linux-amd64 /usr/local/bin/zcloud
zcloud status  # Sanity check
```

**Server (N150):**
```bash
cd ~/Git_Repos/zcloud
git pull
make build-server
sudo systemctl stop zcloud-server
sudo cp dist/zcloud-server-linux-amd64 /opt/zcloud-server/zcloud-server
sudo systemctl start zcloud-server
sudo systemctl status zcloud-server  # Verify it starts cleanly
```

### 🔑 First device bootstrap (first admin)

When you start the server for the first time, you need to approve the first device and make it admin:

```bash
# 1. On the client, initialize and get the device_id (you'll be asked for a user/persona name)
zcloud init https://api.zyrak.cloud
# Note the Device ID shown by the CLI

# 2. On the server, approve the device and assign it to your user/persona
zcloud-server admin devices approve <device_id> --user stefan
# This prints an "Enrollment code" (one-time, expires in ~10 minutes)

# 3. For the first device only, mark it as admin:
sqlite3 /opt/zcloud-server/data/zcloud.db "UPDATE devices SET is_admin=1 WHERE id='<device_id>'"

# 4. On the client, confirm approval
zcloud init --complete

# 5. Configure TOTP (only once per user) using the Enrollment code printed at approval time
zcloud totp ABCD-EFGH-IJKL

# 6. You're ready
zcloud login
zcloud status
```

> 💡 After this initial setup, you can approve new devices on the server with `zcloud-server admin devices approve <id>`.

## 📁 File layout

### Client (`~/.zcloud/`)

```
~/.zcloud/
├── config.yaml      # Client config
├── device.key       # Private key (Ed25519)
├── device.pub       # Public key
└── kubeconfig       # Kubeconfig for kubectl/Powerlevel10k
```

### Server (`/opt/zcloud-server/`)

```
/opt/zcloud-server/
├── zcloud-server    # Binary
├── config.yaml      # Config
├── data/
│   ├── zcloud.db    # SQLite database
│   └── jwt.secret   # JWT secret
└── certs/
    ├── fullchain.pem  # TLS cert
    └── privkey.pem    # TLS private key
```

## ⚙️ Server configuration

```yaml
# /opt/zcloud-server/config.yaml

server:
  host: 0.0.0.0
  port: 443
  domain: api.zyrak.cloud

tls:
  cert: /opt/zcloud-server/certs/fullchain.pem
  key: /opt/zcloud-server/certs/privkey.pem

auth:
  jwt_secret_file: /opt/zcloud-server/data/jwt.secret
  session_ttl: 12h
  totp_issuer: "ZCloud"
  require_approval: true

kubernetes:
  kubeconfig: /etc/rancher/k3s/k3s.yaml
  coredns_ip: 10.43.0.10:53

storage:
  database: /opt/zcloud-server/data/zcloud.db
```

**Kubernetes configuration:**
- `kubeconfig`: path to the k3s kubeconfig file
- `coredns_ip`: CoreDNS service IP for resolving k8s service names (default: `10.43.0.10:53`)
- `ca_cert`: path to the k3s cluster CA certificate (optional)

## 🏥 Health checks

ZCloud exposes health endpoints for monitoring and orchestration:

### `/health` - Liveness
```bash
curl https://api.zyrak.cloud/health
```

Response:
```json
{
  "status": "ok",
  "timestamp": "2025-01-30T14:30:00Z"
}
```

### `/ready` - Readiness
```bash
curl https://api.zyrak.cloud/ready
```

Response (ready):
```json
{
  "status": "ready",
  "timestamp": "2025-01-30T14:30:00Z"
}
```

Response (not ready):
```json
{
  "status": "not_ready",
  "reason": "database_unavailable"
}
```

Possible reasons:
- `database_unavailable`: cannot connect to the database
- `kubernetes_unavailable`: cannot connect to the k8s API

### Orchestrators
```yaml
# Kubernetes livenessProbe
livenessProbe:
  httpGet:
    path: /health
    port: 443
    scheme: HTTPS

# Kubernetes readinessProbe
readinessProbe:
  httpGet:
    path: /ready
    port: 443
    scheme: HTTPS
```

## 🔧 Development

```bash
# Clone
git clone https://github.com/zyrak/zcloud
cd zcloud

# Install deps
make deps

# Build
make build

# Run tests
make test

# Local dev (server)
make dev-server

# Local dev (client)
make dev-client
```

## 🧪 Testing

ZCloud includes unit tests for core components:

```bash
# Run all tests
make test

# Run package-specific tests
go test ./internal/server/db/...
go test ./internal/shared/crypto/...
go test ./internal/server/middleware/...

# Coverage
go test -cover ./...
```

### Test coverage

- **Database Operations**: 20 test cases for CRUD, sessions, and revocation
- **Cryptography**: 13 test cases for key generation, signatures, and TOTP
- **Authentication**: 21 test cases for JWT, middleware, and security
- **Rate Limiting**: 10 test cases including concurrency and expiration

All tests pass, ensuring stability of critical components.

## 📋 API reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/devices/register` | POST | Register a new device |
| `/api/v1/devices/status` | GET | Registration status (no secrets) |
| `/api/v1/totp/enroll` | POST | TOTP enrollment (one-time enrollment code + device signature) |
| `/api/v1/auth/login` | POST | Login |
| `/api/v1/auth/logout` | POST | Logout |
| `/api/v1/status/cluster` | GET | Cluster status |
| `/api/v1/k8s/apply` | POST | Apply manifests |
| `/api/v1/k8s/proxy/*` | ALL | Kubernetes API proxy (no rate limit) |
| `/api/v1/ssh/exec` | POST | Execute a command |
| `/api/v1/admin/devices` | GET | List devices |
| `/api/v1/admin/devices/:id/approve` | POST | Approve device + emit enrollment code (optional `?user=<name>`) |
| `/api/v1/admin/devices/:id/revoke` | POST | Revoke device |

## 🚨 Troubleshooting

### Error: "device not approved"
```bash
# On the server, approve the device
zcloud admin devices approve <device_id> --user stefan

# On the client, complete setup
zcloud init --complete
```

### Error: "invalid TOTP code"
- Make sure your device time is synced (NTP)
- If you lost the TOTP, rotate it on the server and re-enroll (this generates a new enrollment code):
```bash
zcloud-server admin users rotate <user_name> --device <device_id>
zcloud totp ABCD-EFGH-IJKL
```

### Error: "connection refused"
- Check the service: `systemctl status zcloud-server`
- Check the firewall: `ufw status`
- Check TLS/health: `curl -k https://api.zyrak.cloud/health`

### Error: "the server has asked for the client to provide credentials" (Helm)

If you see this error when using Helm:
```
Error: INSTALLATION FAILED: the server has asked for the client to provide credentials
```

This can be caused by:
1. **Expired token**: run `zcloud login` again
2. **Rate limiting** (older versions): update zcloud-server to the latest version
3. **Connection issues**: verify the server is accessible

```bash
# Verify session
zcloud status

# Re-login if needed
zcloud login

# Test connection
kubectl get nodes
```

## 📄 License

MIT

## 🤝 Contributing

1. Fork the repository
2. Create a branch (`git checkout -b feature/my-feature`)
3. Commit (`git commit -am 'Add my feature'`)
4. Push (`git push origin feature/my-feature`)
5. Open a Pull Request