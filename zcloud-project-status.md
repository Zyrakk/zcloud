# ZCLOUD CLI - Estado del Proyecto

> **Versión:** 1.0.0-alpha  
> **Fecha:** Enero 2026  
> **Autor:** Zyrak

---

## 📋 Índice

1. [Resumen del Proyecto](#resumen-del-proyecto)
2. [Arquitectura](#arquitectura)
3. [Estado Actual](#estado-actual)
4. [Estructura de Archivos](#estructura-de-archivos)
5. [Detalle de Cada Archivo](#detalle-de-cada-archivo)
6. [Funcionalidades Pendientes](#funcionalidades-pendientes)
7. [Roadmap de Desarrollo](#roadmap-de-desarrollo)
8. [Guía de Despliegue](#guía-de-despliegue)

---

## Resumen del Proyecto

**ZCloud** es una herramienta CLI para gestionar remotamente un cluster k3s desde cualquier dispositivo Linux, sin necesidad de VPN ni configuración manual de kubeconfig.

### Problema que resuelve

- Acceder al cluster k3s del homelab desde cualquier lugar
- Desplegar aplicaciones sin copiar archivos manualmente al servidor
- Autenticación segura con 2FA
- Gestión centralizada de dispositivos autorizados

### Componentes principales

| Componente | Descripción |
|------------|-------------|
| `zcloud` | CLI cliente que se instala en cualquier Linux |
| `zcloud-server` | API REST que corre en el servidor central (N150) |
| Dominio | `api.zyrak.cloud` para acceso público con TLS |

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FLUJO DE CONEXIÓN                               │
└─────────────────────────────────────────────────────────────────────────────┘

   CLIENTE                           INTERNET                      SERVIDOR
┌───────────────┐                                              ┌───────────────┐
│               │                                              │               │
│  zcloud CLI   │──── HTTPS (TLS 1.3) ────────────────────────►│ zcloud-server │
│               │     api.zyrak.cloud:443                      │               │
│  ~/.zcloud/   │                                              │ /opt/zcloud/  │
│  ├─ config    │◄─────────────────────────────────────────────│ ├─ config     │
│  ├─ keys      │         JWT Token (12h)                      │ ├─ database   │
│  └─ session   │                                              │ └─ certs      │
│               │                                              │       │       │
└───────────────┘                                              └───────┼───────┘
                                                                       │
                                                                       ▼
                                                               ┌───────────────┐
                                                               │  k3s cluster  │
                                                               │               │
                                                               │ ┌───────────┐ │
                                                               │ │  kubectl  │ │
                                                               │ └───────────┘ │
                                                               │               │
                                                               │  4 nodos VPN  │
                                                               └───────────────┘
```

### Flujo de autenticación

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           REGISTRO DE DISPOSITIVO                            │
└─────────────────────────────────────────────────────────────────────────────┘

1. Cliente genera par de claves Ed25519
2. Cliente envía clave pública al servidor
3. Servidor crea registro con estado "pending"
4. Admin aprueba dispositivo
5. Servidor genera secreto TOTP
6. Cliente configura app autenticador (Google Authenticator, etc.)

┌─────────────────────────────────────────────────────────────────────────────┐
│                              LOGIN DIARIO                                    │
└─────────────────────────────────────────────────────────────────────────────┘

1. Cliente firma timestamp con clave privada
2. Cliente envía: device_id + firma + código TOTP
3. Servidor verifica:
   - Firma válida (demuestra posesión de clave privada)
   - TOTP válido (demuestra posesión de secreto)
   - Dispositivo aprobado
4. Servidor devuelve JWT (válido 12 horas)
5. Cliente usa JWT para todas las peticiones
```

---

## Estado Actual

### ✅ Completado (Fase 1 - Core Auth)

| Funcionalidad | Descripción | Estado |
|---------------|-------------|--------|
| Generación de claves | Ed25519 keypair por dispositivo | ✅ |
| Registro de dispositivos | POST /api/v1/devices/register | ✅ |
| Aprobación de dispositivos | Sistema de pending/approved/revoked | ✅ |
| TOTP 2FA | Generación y validación | ✅ |
| Login con firma | Verificación criptográfica | ✅ |
| JWT sessions | Tokens de 12h con claims | ✅ |
| Proxy kubectl | `zcloud k get pods` | ✅ |
| Apply manifests | `zcloud apply file.yaml` | ✅ |
| Exec comandos | `zcloud exec kubectl ...` | ✅ |
| Admin: listar dispositivos | `zcloud admin devices list` | ✅ |
| Admin: aprobar/revocar | `zcloud admin devices approve/revoke` | ✅ |
| Base de datos SQLite | Persistencia de dispositivos y sesiones | ✅ |
| Rate limiting | Prevención de ataques | ✅ |
| Systemd service | Servicio del servidor | ✅ |

### ✅ Completado (Fase 2 - Conectividad)

| Funcionalidad | Descripción | Estado |
|---------------|-------------|--------|
| SSH tunneling | `zcloud ssh` - Shell interactiva via WebSocket | ✅ |
| Transferencia de archivos | `zcloud cp` - Upload/download de archivos | ✅ |

### ⏳ Pendiente

| Funcionalidad | Descripción | Prioridad |
|---------------|-------------|-----------|
| Port forwarding | `zcloud port-forward` | Media |
| DDNS automático | Actualización de IP en Cloudflare | Media |
| Let's Encrypt auto | Renovación automática de certificados | Media |
| Notificaciones Telegram | Alertas de nuevos dispositivos | Baja |
| Logs streaming | `zcloud logs -f` via WebSocket | Baja |
| Métricas del servidor | Endpoint /metrics para Prometheus | Baja |

---

## Estructura de Archivos

```
zcloud/
├── cmd/                          # Puntos de entrada (main)
│   ├── zcloud/                   # CLI cliente
│   │   └── main.go              
│   └── zcloud-server/            # Servidor API
│       └── main.go              
│
├── internal/                     # Código interno (no exportado)
│   ├── client/                   # Lógica del cliente
│   │   ├── auth.go              
│   │   ├── config.go            
│   │   ├── files.go             # [NUEVO] Transferencia de archivos
│   │   ├── http.go              
│   │   └── ssh.go               # [NUEVO] Cliente SSH WebSocket
│   │
│   ├── server/                   # Lógica del servidor
│   │   ├── api/
│   │   │   ├── files.go         # [NUEVO] Handlers de archivos
│   │   │   ├── handlers.go      
│   │   │   └── ssh.go           # [NUEVO] Handler SSH con PTY
│   │   ├── db/
│   │   │   └── database.go      
│   │   └── middleware/
│   │       └── auth.go          
│   │
│   └── shared/                   # Código compartido cliente/servidor
│       ├── crypto/
│       │   ├── keys.go          
│       │   └── totp.go          
│       └── protocol/
│           └── types.go         # Incluye tipos SSH y Files
│
├── scripts/                      # Scripts de instalación
│   ├── install-server.sh        
│   └── install-client.sh        
│
├── configs/                      # Archivos de configuración
│   └── zcloud-server.service    
│
├── go.mod                        # Dependencias Go
├── Makefile                      # Comandos de build
├── .gitignore                   
└── README.md                    
```

---

## Detalle de Cada Archivo

### 📁 cmd/zcloud/main.go

**Propósito:** Punto de entrada del CLI cliente.

**Funcionalidades:**
- Parseo de comandos con Cobra
- Subcomandos: `init`, `login`, `logout`, `status`, `k`, `apply`, `exec`, `admin`
- Carga de configuración desde `~/.zcloud/`
- Gestión de errores y códigos de salida

**Comandos implementados:**

| Comando | Descripción |
|---------|-------------|
| `zcloud init <url>` | Configura el cliente por primera vez |
| `zcloud init --complete` | Completa config después de aprobación |
| `zcloud login` | Inicia sesión con TOTP |
| `zcloud logout` | Cierra sesión |
| `zcloud status` | Muestra estado del cluster |
| `zcloud k <args>` | Proxy a kubectl |
| `zcloud apply <file>` | Aplica manifests YAML |
| `zcloud exec <cmd>` | Ejecuta comando en servidor |
| `zcloud admin devices list` | Lista dispositivos |
| `zcloud admin devices approve <id>` | Aprueba dispositivo |
| `zcloud admin devices revoke <id>` | Revoca dispositivo |

---

### 📁 cmd/zcloud-server/main.go

**Propósito:** Punto de entrada del servidor API.

**Funcionalidades:**
- Carga de configuración YAML
- Inicialización de base de datos
- Configuración de TLS
- Servidor HTTP con graceful shutdown
- Limpieza periódica de sesiones expiradas
- Modo `--init` para primera configuración

**Configuración soportada:**

```yaml
server:
  host: 0.0.0.0
  port: 443
  domain: api.zyrak.cloud

tls:
  cert: /path/to/cert.pem
  key: /path/to/key.pem

auth:
  jwt_secret_file: /path/to/jwt.secret
  session_ttl: 12h
  totp_issuer: "ZCloud"
  require_approval: true

kubernetes:
  kubeconfig: /etc/rancher/k3s/k3s.yaml

storage:
  database: /path/to/zcloud.db
```

---

### 📁 internal/client/auth.go

**Propósito:** Maneja toda la lógica de autenticación del cliente.

**Funciones principales:**

| Función | Descripción |
|---------|-------------|
| `Init(serverURL)` | Genera claves, registra dispositivo |
| `CompleteInit()` | Configura TOTP después de aprobación |
| `Login()` | Firma timestamp, envía TOTP, obtiene JWT |
| `Logout()` | Invalida sesión local y remota |
| `Status()` | Muestra estado de sesión y cluster |
| `EnsureSession()` | Verifica que hay sesión válida |

**Flujo de Init:**
1. Genera keypair Ed25519
2. Guarda en `~/.zcloud/device.key` y `device.pub`
3. Envía clave pública al servidor
4. Guarda device_id en config
5. Si require_approval=true, espera aprobación

**Flujo de Login:**
1. Carga keypair desde disco
2. Firma timestamp actual con clave privada
3. Pide código TOTP al usuario
4. Envía device_id + firma + TOTP
5. Recibe y guarda JWT

---

### 📁 internal/client/config.go

**Propósito:** Gestión de la configuración local del cliente.

**Estructura de configuración:**

```go
type Config struct {
    Server struct {
        URL      string  // https://api.zyrak.cloud
        Insecure bool    // Skip TLS verify (desarrollo)
    }
    Device struct {
        ID       string  // ID único del dispositivo
        Name     string  // Nombre friendly
        Approved bool    // Si está aprobado
    }
    Session struct {
        Token     string    // JWT actual
        ExpiresAt time.Time // Expiración
    }
}
```

**Funciones:**

| Función | Descripción |
|---------|-------------|
| `LoadConfig(dir)` | Carga config desde ~/.zcloud/ |
| `Save()` | Guarda config a disco |
| `IsInitialized()` | Verifica si hay device_id y server_url |
| `IsApproved()` | Verifica si dispositivo está aprobado |
| `HasValidSession()` | Verifica si JWT no ha expirado |
| `SetSession(token, expires)` | Guarda nueva sesión |
| `ClearSession()` | Limpia sesión actual |

---

### 📁 internal/client/http.go

**Propósito:** Cliente HTTP para comunicación con el servidor.

**Funciones:**

| Función | Descripción |
|---------|-------------|
| `Register(req)` | POST /api/v1/devices/register |
| `GetDeviceStatus(id)` | GET /api/v1/devices/status |
| `Login(req)` | POST /api/v1/auth/login |
| `Logout()` | POST /api/v1/auth/logout |
| `GetStatus()` | GET /api/v1/status/cluster |
| `Apply(req)` | POST /api/v1/k8s/apply |
| `Exec(req)` | POST /api/v1/ssh/exec |
| `KubectlProxy(args)` | Wrapper para comandos kubectl |
| `ListDevices()` | GET /api/v1/admin/devices |
| `ApproveDevice(id)` | POST /api/v1/admin/devices/:id/approve |
| `RevokeDevice(id)` | POST /api/v1/admin/devices/:id/revoke |

**Headers automáticos:**
- `Authorization: Bearer <JWT>` (si hay sesión)
- `X-Device-ID: <device_id>` (si está configurado)
- `Content-Type: application/json`

---

### 📁 internal/server/api/handlers.go

**Propósito:** Handlers de todos los endpoints de la API REST.

**Endpoints públicos (sin auth):**

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v1/devices/register` | POST | Registrar nuevo dispositivo |
| `/api/v1/devices/status` | GET | Estado de registro |
| `/api/v1/auth/login` | POST | Iniciar sesión |
| `/health` | GET | Health check |

**Endpoints protegidos (requieren JWT):**

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v1/auth/logout` | POST | Cerrar sesión |
| `/api/v1/status/cluster` | GET | Estado del cluster |
| `/api/v1/k8s/apply` | POST | Aplicar manifests |
| `/api/v1/ssh/exec` | POST | Ejecutar comando |

**Endpoints admin (requieren JWT + is_admin=true):**

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v1/admin/devices` | GET | Listar dispositivos |
| `/api/v1/admin/devices/:id/approve` | POST | Aprobar dispositivo |
| `/api/v1/admin/devices/:id/revoke` | POST | Revocar dispositivo |
| `/api/v1/admin/sessions` | GET | Listar sesiones activas |

**Validaciones de seguridad:**
- Verificación de firma Ed25519 en login
- Validación de TOTP con ventana de tiempo
- Verificación de timestamp (±5 minutos) para prevenir replay attacks
- Whitelist de comandos permitidos en exec (kubectl, helm, k3s)

---

### 📁 internal/server/db/database.go

**Propósito:** Capa de acceso a datos con SQLite.

**Tablas:**

```sql
-- Dispositivos registrados
CREATE TABLE devices (
    id TEXT PRIMARY KEY,           -- Hash de la clave pública
    name TEXT NOT NULL,            -- Nombre del dispositivo
    public_key TEXT NOT NULL,      -- Clave pública Ed25519 (base64)
    hostname TEXT,                 -- Hostname del sistema
    os TEXT,                       -- linux/amd64, darwin/arm64, etc.
    status TEXT DEFAULT 'pending', -- pending, approved, revoked
    totp_secret TEXT,              -- Secreto TOTP (base32)
    created_at DATETIME,
    last_access DATETIME,
    is_admin INTEGER DEFAULT 0
);

-- Sesiones activas
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,           -- UUID
    device_id TEXT NOT NULL,       -- FK a devices
    token_hash TEXT NOT NULL,      -- Hash SHA256 del JWT
    expires_at DATETIME NOT NULL,
    created_at DATETIME,
    ip_address TEXT
);
```

**Funciones principales:**

| Función | Descripción |
|---------|-------------|
| `CreateDevice(device, totpSecret)` | Registra nuevo dispositivo |
| `GetDevice(id)` | Obtiene dispositivo por ID |
| `GetDeviceByPublicKey(key)` | Busca por clave pública |
| `UpdateDeviceStatus(id, status)` | Cambia estado |
| `UpdateDeviceTOTP(id, secret)` | Guarda secreto TOTP |
| `ListDevices()` | Lista todos los dispositivos |
| `IsAdmin(id)` | Verifica si es admin |
| `CreateSession(...)` | Registra nueva sesión |
| `DeleteDeviceSessions(id)` | Invalida sesiones |
| `CleanExpiredSessions()` | Limpieza periódica |

---

### 📁 internal/server/middleware/auth.go

**Propósito:** Middlewares de autenticación y seguridad.

**Middlewares:**

| Middleware | Descripción |
|------------|-------------|
| `Authenticate` | Verifica JWT en header Authorization |
| `RequireAdmin` | Verifica claim is_admin=true |
| `RateLimiter.Limit` | Limita requests por IP |
| `CORS` | Añade headers CORS |
| `Logger` | Log de requests |

**JWT Claims:**

```go
type JWTClaims struct {
    DeviceID   string
    DeviceName string
    IsAdmin    bool
    jwt.RegisteredClaims  // exp, iat, iss
}
```

**Funciones de token:**

| Función | Descripción |
|---------|-------------|
| `GenerateToken(deviceID, name, isAdmin, duration)` | Crea JWT firmado |
| `ValidateToken(tokenString)` | Verifica y parsea JWT |

---

### 📁 internal/shared/crypto/keys.go

**Propósito:** Gestión de claves criptográficas Ed25519.

**Funciones:**

| Función | Descripción |
|---------|-------------|
| `GenerateKeyPair()` | Genera nuevo par Ed25519 |
| `KeyPair.Sign(message)` | Firma mensaje |
| `KeyPair.PublicKeyString()` | Exporta pubkey en base64 |
| `KeyPair.SaveToFiles(dir)` | Guarda a device.key/device.pub |
| `LoadFromFiles(dir)` | Carga desde disco |
| `VerifySignature(pubkey, msg, sig)` | Verifica firma |
| `GenerateDeviceID(pubkey)` | Genera ID desde pubkey |
| `GenerateRandomSecret(len)` | Genera secreto aleatorio |

---

### 📁 internal/shared/crypto/totp.go

**Propósito:** Generación y validación de códigos TOTP.

**Funciones:**

| Función | Descripción |
|---------|-------------|
| `GenerateTOTP(config)` | Genera secreto + QR code |
| `ValidateTOTP(secret, code)` | Valida código de 6 dígitos |
| `GetTOTPURL(secret, config)` | Genera URL otpauth:// |

**Configuración TOTP:**
- Algoritmo: SHA1
- Dígitos: 6
- Período: 30 segundos
- Compatible con: Google Authenticator, Authy, 1Password, etc.

---

### 📁 internal/shared/protocol/types.go

**Propósito:** Estructuras de datos compartidas entre cliente y servidor.

**Estructuras principales:**

```go
// Estados de dispositivo
type DeviceStatus string
const (
    DeviceStatusPending  = "pending"
    DeviceStatusApproved = "approved"
    DeviceStatusRevoked  = "revoked"
)

// Petición de registro
type RegisterRequest struct {
    DeviceName string
    PublicKey  string  // Ed25519 base64
    Hostname   string
    OS         string
}

// Petición de login
type LoginRequest struct {
    DeviceID  string
    Timestamp int64   // Unix timestamp
    Signature string  // Firma del timestamp
    TOTPCode  string  // Código de 6 dígitos
}

// Respuesta de login
type LoginResponse struct {
    Token     string
    ExpiresAt time.Time
}

// Estado del cluster
type StatusResponse struct {
    Connected   bool
    ClusterName string
    Nodes       []NodeInfo
    Session     SessionInfo
}

// Petición de apply
type ApplyRequest struct {
    Manifests []string  // Contenido YAML
    Namespace string
    DryRun    bool
}

// Petición de exec
type ExecRequest struct {
    Command string
    Args    []string
    WorkDir string
}
```

---

### 📁 scripts/install-server.sh

**Propósito:** Script de instalación automatizada del servidor.

**Acciones:**
1. Verifica root y dependencias (kubectl/k3s)
2. Crea directorios en /opt/zcloud-server/
3. Descarga o copia binario
4. Genera configuración interactiva
5. Inicializa base de datos
6. Instala servicio systemd
7. Configura firewall (UFW)
8. Muestra instrucciones para TLS

---

### 📁 scripts/install-client.sh

**Propósito:** Script de instalación del cliente.

**Acciones:**
1. Detecta OS y arquitectura
2. Descarga binario correcto
3. Instala en /usr/local/bin/
4. Muestra instrucciones de uso

---

### 📁 configs/zcloud-server.service

**Propósito:** Unit file de systemd para el servidor.

**Características:**
- Reinicio automático en caso de fallo
- Hardening de seguridad (NoNewPrivileges, ProtectSystem)
- Logging a journald
- Dependencia de network y k3s

---

### 📁 Makefile

**Propósito:** Automatización de build y deployment.

**Targets:**

| Target | Descripción |
|--------|-------------|
| `make build` | Compila cliente y servidor |
| `make build-client` | Solo cliente (amd64 + arm64) |
| `make build-server` | Solo servidor |
| `make install-client` | Instala cliente en /usr/local/bin |
| `make install-server` | Instala servidor en /opt/zcloud-server |
| `make test` | Ejecuta tests |
| `make clean` | Limpia binarios |

---

## Funcionalidades Implementadas (Fase 2)

### ✅ SSH Tunneling (`zcloud ssh`) - COMPLETADO

**Descripción:** Conexión SSH interactiva al servidor a través de WebSocket.

**Uso:**
```bash
zcloud ssh
```

**Implementación:**

| Archivo | Descripción |
|---------|-------------|
| `internal/client/ssh.go` | Cliente WebSocket con terminal raw mode y resize polling |
| `internal/server/api/ssh.go` | Handler WebSocket con PTY (`/bin/bash`) |

**Características:**
- Conexión bidireccional via WebSocket
- Terminal mode raw con restauración al salir
- Detección automática de resize de terminal (polling cada 500ms)
- Compatible con cross-compilation (Windows → Linux)

**Protocolo:**
```go
type SSHMessage struct {
    Type SSHMessageType `json:"type"`  // input, output, resize, error, close
    Data []byte         `json:"data,omitempty"`
    Rows uint16         `json:"rows,omitempty"`
    Cols uint16         `json:"cols,omitempty"`
}
```

---

### ✅ Transferencia de Archivos (`zcloud cp`) - COMPLETADO

**Descripción:** Copiar archivos entre local y servidor.

**Uso:**
```bash
zcloud cp archivo.txt remote:/ruta/destino/
zcloud cp remote:/ruta/archivo.txt ./local/
zcloud cp -r ./carpeta/ remote:/destino/
```

**Implementación:**

| Archivo | Descripción |
|---------|-------------|
| `internal/client/files.go` | Cliente HTTP con upload multipart y download streaming |
| `internal/server/api/files.go` | Handlers para upload, download, list y delete |

**Endpoints:**
- `POST /api/v1/files/upload` - Multipart form upload
- `GET /api/v1/files/download?path=` - Stream download
- `GET /api/v1/files/list?path=` - Listar archivos
- `DELETE /api/v1/files/delete` - Eliminar archivos

**Características:**
- Upload multipart con checksum SHA256
- Download streaming con verificación
- Listado recursivo de directorios
- Protección contra path traversal
- Límite de 100MB por archivo

---

## Funcionalidades Pendientes

### 🟡 Media Prioridad

#### 3. Port Forwarding (`zcloud port-forward`)

**Descripción:** Forward de puertos locales a servicios del cluster.

```bash
zcloud port-forward grafana 3000:3000
# Acceder a http://localhost:3000
```

**Implementación:**
- WebSocket bidireccional para tunnel TCP
- Listener local que conecta al WebSocket
- Servidor proxy al servicio destino

---

#### 4. DDNS Automático

**Descripción:** Actualizar IP pública en Cloudflare automáticamente.

**Implementación:**
```go
// internal/server/ddns/cloudflare.go
type CloudflareDDNS struct {
    APIToken string
    ZoneID   string
    Record   string
}

func (d *CloudflareDDNS) UpdateIP() error {
    // 1. Obtener IP pública actual
    // 2. Comparar con registro DNS
    // 3. Actualizar si es diferente
}
```

**Configuración:**
```yaml
ddns:
  enabled: true
  provider: cloudflare
  api_token: "xxx"
  zone_id: "xxx"
  record: api.zyrak.cloud
  update_interval: 5m
```

---

#### 5. Renovación Automática de Certificados

**Descripción:** Integración con certbot para renovar Let's Encrypt.

**Implementación:**
- Cron job o timer systemd
- Hook post-renovación para reload del servidor
- Verificación de expiración en health check

---

### 🟢 Baja Prioridad

#### 6. Notificaciones Telegram

**Descripción:** Alertas cuando se registra un nuevo dispositivo.

```go
// internal/server/notifications/telegram.go
func SendNewDeviceAlert(device DeviceInfo) error {
    msg := fmt.Sprintf("🆕 Nuevo dispositivo: %s\nID: %s\nAprobar: zcloud admin devices approve %s",
        device.Name, device.ID, device.ID)
    // Enviar via Bot API
}
```

---

#### 7. Logs Streaming (`zcloud logs -f`)

**Descripción:** Ver logs de pods en tiempo real via WebSocket.

```bash
zcloud logs grafana -f
zcloud logs -n monitoring victoria -f
```

---

#### 8. Métricas Prometheus

**Descripción:** Endpoint /metrics para monitorizar el servidor.

Métricas a exponer:
- Requests totales por endpoint
- Latencia de requests
- Dispositivos activos
- Sesiones activas
- Errores de autenticación

---

## Roadmap de Desarrollo

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ROADMAP                                        │
└─────────────────────────────────────────────────────────────────────────────┘

FASE 1 - Core Auth ✅ COMPLETADA
├── Device registration
├── TOTP 2FA
├── JWT sessions
├── kubectl proxy
└── Apply manifests

FASE 2 - Conectividad ✅ COMPLETADA (Enero 2026)
├── ✅ SSH tunneling (zcloud ssh)
├── ✅ File transfer (zcloud cp)
└── ⏳ Port forwarding (pendiente)

FASE 3 - Operaciones (Próxima)
├── DDNS automático
├── Let's Encrypt auto
└── Logs streaming

FASE 4 - Observabilidad
├── Notificaciones Telegram
├── Métricas Prometheus
└── Dashboard web (opcional)

FASE 5 - Extras
├── Soporte Windows/macOS
├── Sincronización de proyectos
└── CI/CD integration
```

---

## Guía de Despliegue

### Requisitos Previos

**Servidor (N150):**
- Ubuntu 24.04 o similar
- k3s instalado y funcionando
- Puerto 443 accesible desde internet
- Dominio apuntando a IP pública

**Cliente:**
- Cualquier Linux con glibc
- Go 1.22+ (solo para compilar)

### Pasos de Despliegue

```bash
# 1. Clonar y compilar
git clone https://github.com/zyrak/zcloud
cd zcloud
make build

# 2. Instalar servidor (en N150)
scp dist/zcloud-server-linux-amd64 n150:/tmp/
ssh n150
sudo ./scripts/install-server.sh

# 3. Configurar TLS
sudo certbot certonly --standalone -d api.zyrak.cloud
sudo ln -sf /etc/letsencrypt/live/api.zyrak.cloud/*.pem /opt/zcloud-server/certs/

# 4. Iniciar servidor
sudo systemctl enable --now zcloud-server

# 5. Instalar cliente (en tu portátil)
sudo cp dist/zcloud-linux-amd64 /usr/local/bin/zcloud

# 6. Configurar cliente
zcloud init https://api.zyrak.cloud

# 7. Aprobar primer dispositivo (en N150)
sqlite3 /opt/zcloud-server/data/zcloud.db \
  "UPDATE devices SET is_admin=1, status='approved' WHERE id='TU_DEVICE_ID'"

# 8. Completar setup
zcloud init --complete
zcloud login
zcloud status
```

---

## Conclusión

ZCloud Fases 1 y 2 proporcionan una herramienta completa con:

### ✅ Fase 1 - Core Auth (Completada)
- Autenticación segura (Ed25519 + TOTP + JWT)
- Proxy de kubectl funcional
- Gestión de dispositivos
- Sistema de permisos (admin/user)

### ✅ Fase 2 - Conectividad (Completada - Enero 2026)
- SSH shell interactiva via WebSocket (`zcloud ssh`)
- Transferencia de archivos bidireccional (`zcloud cp`)

### ⏳ Próximos pasos
Las fases siguientes añadirán:
- Port forwarding para servicios del cluster
- DDNS automático (Cloudflare)
- Renovación automática de certificados Let's Encrypt
- Notificaciones y métricas