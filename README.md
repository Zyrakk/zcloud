# ZCloud CLI

Sistema de gestión remota para clusters k3s. Permite conectarte y administrar tu homelab desde cualquier lugar de forma segura.

## 🏗️ Arquitectura

```
┌─────────────────────────────┐          ┌─────────────────────────────┐
│  CLIENTE (cualquier Linux)  │          │  SERVIDOR (N150)            │
│                             │          │                             │
│  zcloud CLI                 │  HTTPS   │  zcloud-server              │
│  - Device keys (Ed25519)    │◄────────►│  - API REST                 │
│  - TOTP 2FA                 │   :443   │  - JWT sessions             │
│  - kubectl proxy            │          │  - kubectl proxy            │
│                             │          │  - Device management        │
└─────────────────────────────┘          └──────────┬──────────────────┘
                                                    │
                                                    ▼
                                         ┌─────────────────────┐
                                         │  k3s cluster        │
                                         │  (4 nodos via VPN)  │
                                         └─────────────────────┘
```

## 🔐 Seguridad

| Capa | Mecanismo | Propósito |
|------|-----------|-----------|
| 1 | TLS 1.3 | Cifrado en tránsito |
| 2 | Device Key (Ed25519) | Identifica el dispositivo |
| 3 | TOTP | Verifica que es el usuario |
| 4 | JWT (12h TTL) | Sesión temporal |
| 5 | Token Revocation | Invalidación inmediata de sesiones |
| 6 | Security Headers | Protección XSS, clickjacking, etc. |
| 7 | Rate limiting | Previene ataques |
| 8 | Audit Logging | Rastro de seguridad |

### Token Revocation

ZCloud incluye un sistema de revocación de tokens JWT que permite invalidar sesiones inmediatamente:

- **Logout explícito**: Los tokens se revocan al ejecutar `zcloud stop`
- **Revocación de dispositivo**: Todos los tokens de un dispositivo se revocan al revocarlo
- **Blacklist automático**: Sistema de blacklist para tokens revocados
- **Limpieza automática**: Tokens revocados expirados se eliminan automáticamente

Esto garantiza que los tokens no pueden ser reutilizados después de un logout o revocación, mejorando significativamente la seguridad.

### Security Headers

ZCloud implementa headers de seguridad HTTP para proteger contra ataques comunes:

- **Content-Security-Policy (CSP)**: Previene ataques XSS
- **X-Frame-Options: DENY**: Previene clickjacking
- **X-Content-Type-Options: nosniff**: Previene MIME-sniffing
- **X-XSS-Protection**: Protección XSS adicional
- **Strict-Transport-Security (HSTS)**: Previene downgrade HTTPS
- **Referrer-Policy**: Privacidad de referer
- **Permissions-Policy**: Control de características del navegador

### TLS Verification

ZCloud ahora valida correctamente los certificados TLS del cluster k3s:

- **Verificación de CA**: Utiliza certificados CA válidos en lugar de `InsecureSkipVerify`
- **Soporte para CA personalizada**: Configurable vía `kubernetes.ca_cert`
- **Autodetección**: Descubre CA del kubeconfig si no se especifica
- **Seguridad**: Previene ataques MITM en la comunicación con k3s

### Audit Logging

ZCloud registra eventos de seguridad importantes para auditoría:

- **Eventos registrados**: Registro de dispositivos, login, logout, aprobación, revocación
- **Configurable**: Nivel de log ajustable (debug/info/warn/error/disabled)
- **Timestamped**: Todos los eventos incluyen fecha/hora precisa
- **Detalles**: Incluye device ID, IP y detalles adicionales

Ejemplo de logs:
```
[2025-01-30 14:30:00] AUDIT: device_registered device=a1b2c3d4e5f6 details=name=my-laptop
[2025-01-30 14:30:15] AUDIT: login_success device=a1b2c3d4e5f6 details=ip=192.168.1.100
[2025-01-30 14:45:22] AUDIT: logout device=a1b2c3d4e5f6 details=ip=192.168.1.100
```

## 📦 Instalación

### Servidor (N150)

```bash
# Opción 1: Script de instalación
curl -fsSL https://api.zyrak.cloud/install-server.sh | sudo bash

# Opción 2: Manual
git clone https://github.com/zyrak/zcloud
cd zcloud
make build-server
sudo make install-server
sudo /opt/zcloud-server/zcloud-server --init
```

### Cliente (cualquier Linux)

```bash
# Opción 1: Script de instalación
curl -fsSL https://api.zyrak.cloud/install.sh | bash

# Opción 2: Manual
git clone https://github.com/zyrak/zcloud
cd zcloud
make build-client
sudo make install-client
```

## 🚀 Uso

### Primera configuración (cliente)

```bash
# 1. Inicializar cliente
zcloud init https://api.zyrak.cloud

# 2. En el SERVIDOR, aprobar el dispositivo
zcloud-server admin devices approve <device_id>

# 3. En el cliente, verificar aprobación
zcloud init --complete

# 4. Configurar TOTP
zcloud totp

# 5. Configurar shell (añadir a ~/.zshrc o ~/.bashrc)
echo 'export KUBECONFIG="$HOME/.zcloud/kubeconfig:$KUBECONFIG"' >> ~/.zshrc
source ~/.zshrc
```

### Uso diario

```bash
# Iniciar sesión (una vez al día, pide TOTP)
zcloud start

# Ahora puedes usar kubectl directamente!
kubectl get pods -A
kubectl get nodes
kubectl describe pod <pod>

# También funciona el proxy interno
zcloud k get pods -A

# Estado del cluster y sesión
zcloud status

# Aplicar manifests
zcloud apply ./deployment.yaml
zcloud apply ./k8s/

# Cerrar sesión (opcional)
zcloud stop
```

> 💡 **Powerlevel10k**: Después de `zcloud start`, tu prompt mostrará `☸ zcloud-homelab`

### Administración

```bash
# Listar dispositivos
zcloud admin devices list

# Aprobar dispositivo pendiente
zcloud admin devices approve <device_id>

# Revocar dispositivo
zcloud admin devices revoke <device_id>
```

### 🔄 Actualización del binario

Cuando hay nuevas versiones disponibles, sigue estos pasos para actualizar:

**Cliente (cualquier Linux):**
```bash
cd ~/Git_Repos/zcloud  # O donde tengas el repositorio
git pull
make build-client
sudo cp dist/zcloud-linux-amd64 /usr/local/bin/zcloud
zcloud status  # Verificar que funciona
```

**Servidor (N150):**
```bash
cd ~/Git_Repos/zcloud
git pull
make build-server
sudo systemctl stop zcloud-server
sudo cp dist/zcloud-server-linux-amd64 /opt/zcloud-server/zcloud-server
sudo systemctl start zcloud-server
sudo systemctl status zcloud-server  # Verificar que arranca bien
```

### 🔑 Primera autorización de dispositivo

Cuando inicias el servidor por primera vez, necesitas aprobar el primer dispositivo manualmente:

```bash
# 1. En el cliente, inicializa y obtén el device_id
zcloud init https://api.zyrak.cloud
# Anota el Device ID que te muestra

# 2. En el servidor, aprobar el dispositivo y marcarlo como admin
zcloud-server admin devices approve <device_id>
# Para el primer dispositivo, también debes marcarlo como admin:
sqlite3 /opt/zcloud-server/data/zcloud.db "UPDATE devices SET is_admin=1 WHERE id='<device_id>'"

# 3. En el cliente, verificar aprobación
zcloud init --complete

# 4. Configurar TOTP
zcloud totp

# 5. Ya puedes usar zcloud normalmente
zcloud login
zcloud status
```

> 💡 **Después de esta configuración inicial**, podrás aprobar nuevos dispositivos directamente en el servidor con `zcloud-server admin devices approve <id>`.

## 📁 Estructura de archivos

### Cliente (`~/.zcloud/`)

```
~/.zcloud/
├── config.yaml      # Configuración del cliente
├── device.key       # Clave privada (Ed25519)
├── device.pub       # Clave pública
└── kubeconfig       # Kubeconfig para kubectl/Powerlevel10k
```

### Servidor (`/opt/zcloud-server/`)

```
/opt/zcloud-server/
├── zcloud-server    # Binario
├── config.yaml      # Configuración
├── data/
│   ├── zcloud.db    # Base de datos SQLite
│   └── jwt.secret   # Secreto JWT
└── certs/
    ├── fullchain.pem  # Certificado TLS
    └── privkey.pem    # Clave privada TLS
```

## ⚙️ Configuración del servidor

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

**Configuración Kubernetes:**
- `kubeconfig`: Path al archivo kubeconfig de k3s
- `coredns_ip`: IP del servicio CoreDNS para resolución de servicios k8s (default: `10.43.0.10:53`)
   - Ajustar si tu cluster k3s usa una IP diferente para CoreDNS
   - Necesario para que funcione el port forwarding a servicios k8s
- `ca_cert`: Path al certificado CA del cluster k3s (opcional)
   - Si se especifica, se usa para verificar las conexiones TLS al cluster k3s
   - Si no se especifica, se intenta extraer del kubeconfig automáticamente
   - Mejora la seguridad al validar certificados en lugar de usar InsecureSkipVerify

## 🏥 Health Checks

ZCloud expone endpoints de salud para monitoreo y orquestación:

### `/health` - Liveness check
```bash
curl https://api.zyrak.cloud/health
```

Respuesta:
```json
{
  "status": "ok",
  "timestamp": "2025-01-30T14:30:00Z"
}
```

### `/ready` - Readiness check
```bash
curl https://api.zyrak.cloud/ready
```

Respuesta (cuando está listo):
```json
{
  "status": "ready",
  "timestamp": "2025-01-30T14:30:00Z"
}
```

Respuesta (cuando hay problemas):
```json
{
  "status": "not_ready",
  "reason": "database_unavailable"
}
```

Posibles razones:
- `database_unavailable`: No se puede conectar a la base de datos
- `kubernetes_unavailable`: No se puede conectar a la API de k8s

### Uso con orquestadores
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

## 🔧 Desarrollo

```bash
# Clonar repositorio
git clone https://github.com/zyrak/zcloud
cd zcloud

# Instalar dependencias
make deps

# Compilar
make build

# Ejecutar tests
make test

# Desarrollo local (servidor)
make dev-server

# Desarrollo local (cliente)
make dev-client
```

## 🧪 Testing

ZCloud incluye un conjunto completo de pruebas unitarias para garantizar la calidad y estabilidad del código:

```bash
# Ejecutar todas las pruebas
make test

# Ejecutar pruebas de un paquete específico
go test ./internal/server/db/...
go test ./internal/shared/crypto/...
go test ./internal/server/middleware/...

# Ejecutar pruebas con cobertura
go test -cover ./...
```

### Cobertura de Pruebas

- **Database Operations**: 20 casos de prueba para operaciones CRUD, sesiones y revocación
- **Cryptography**: 13 casos de prueba para generación de claves, firmas y TOTP
- **Authentication**: 21 casos de prueba para JWT, middleware y seguridad
- **Rate Limiting**: 10 casos de prueba incluyendo concurrencia y expiración

Todas las pruebas pasan con éxito, garantizando la estabilidad de los componentes críticos.

## 📋 API Reference

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v1/devices/register` | POST | Registrar nuevo dispositivo |
| `/api/v1/devices/status` | GET | Estado del registro |
| `/api/v1/auth/login` | POST | Iniciar sesión |
| `/api/v1/auth/logout` | POST | Cerrar sesión |
| `/api/v1/status/cluster` | GET | Estado del cluster |
| `/api/v1/k8s/apply` | POST | Aplicar manifests |
| `/api/v1/k8s/proxy/*` | ALL | Proxy a API de Kubernetes |
| `/api/v1/ssh/exec` | POST | Ejecutar comando |
| `/api/v1/admin/devices` | GET | Listar dispositivos |
| `/api/v1/admin/devices/:id/approve` | POST | Aprobar dispositivo |
| `/api/v1/admin/devices/:id/revoke` | POST | Revocar dispositivo |

## 🚨 Troubleshooting

### Error: "device not approved"
```bash
# En el servidor, aprobar el dispositivo
zcloud admin devices approve <device_id>

# En el cliente, completar configuración
zcloud init --complete
```

### Error: "invalid TOTP code"
- Verifica que la hora de tu dispositivo está sincronizada (NTP)
- Regenera el TOTP si es necesario

### Error: "connection refused"
- Verifica que el servidor está corriendo: `systemctl status zcloud-server`
- Verifica el firewall: `ufw status`
- Verifica TLS: `curl -k https://api.zyrak.cloud/health`

## 📄 Licencia

MIT

## 🤝 Contribuir

1. Fork el repositorio
2. Crea una rama (`git checkout -b feature/mi-feature`)
3. Commit (`git commit -am 'Add mi-feature'`)
4. Push (`git push origin feature/mi-feature`)
5. Abre un Pull Request