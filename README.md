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
| 5 | Rate limiting | Previene ataques |

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

# 2. Esperar aprobación del admin (en el servidor)
zcloud admin devices approve <device_id>

# 3. Completar configuración (configurar TOTP)
zcloud init --complete

# 4. Login
zcloud login
```

### Comandos diarios

```bash
# Estado del cluster
zcloud status

# Comandos kubectl
zcloud k get pods -A
zcloud k get nodes
zcloud k describe pod <pod>

# Aplicar manifests
zcloud apply ./deployment.yaml
zcloud apply ./k8s/

# Ejecutar comandos
zcloud exec kubectl get nodes
```

### Administración

```bash
# Listar dispositivos
zcloud admin devices list

# Aprobar dispositivo pendiente
zcloud admin devices approve <device_id>

# Revocar dispositivo
zcloud admin devices revoke <device_id>
```

## 📁 Estructura de archivos

### Cliente (`~/.zcloud/`)

```
~/.zcloud/
├── config.yaml      # Configuración del cliente
├── device.key       # Clave privada (Ed25519)
├── device.pub       # Clave pública
└── session.token    # JWT de sesión activa
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
  require_approval: true  # Los nuevos dispositivos requieren aprobación

kubernetes:
  kubeconfig: /etc/rancher/k3s/k3s.yaml

storage:
  database: /opt/zcloud-server/data/zcloud.db
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

## 📋 API Reference

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/v1/devices/register` | POST | Registrar nuevo dispositivo |
| `/api/v1/devices/status` | GET | Estado del registro |
| `/api/v1/auth/login` | POST | Iniciar sesión |
| `/api/v1/auth/logout` | POST | Cerrar sesión |
| `/api/v1/status/cluster` | GET | Estado del cluster |
| `/api/v1/k8s/apply` | POST | Aplicar manifests |
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
