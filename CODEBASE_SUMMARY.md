# ZCloud

## Qué es
CLI y servidor para gestionar clusters k3s de forma remota y segura.

## Stack
| Capa | Tecnología | Versión |
|------|-----------|---------|
| Lenguaje | Go | 1.22 |
| Framework | Cobra (CLI), net/http (server) | - |
| DB | SQLite | modernc.org/sqlite |
| Auth | JWT + TOTP + Ed25519 | golang-jwt/jwt, pquerna/otp |
| Testing | Go testing | - |
| WebSocket | Gorilla WebSocket | - |

## Arquitectura
Cliente-servidor con autenticación mutua. Cliente usa Cobra CLI, servidor expite API REST + WebSockets. Los dispositivos se registran con clave Ed25519, requieren aprobación admin, y usan TOTP para sesiones JWT de 12h.

## Mapa de carpetas
```
/cmd/zcloud → Cliente CLI (22KB main.go)
/cmd/zcloud-server → Servidor HTTP/WebSocket (17KB main.go)
/internal/client → Lógica cliente: auth, config, ssh, portforward, files
/internal/server/api → Handlers HTTP: auth, k8s proxy, ssh, portforward
/internal/server/db → SQLite: devices, sessions, tokens revoked
/internal/server/middleware → JWT auth, rate limiting
/internal/shared/crypto → Ed25519 keys, TOTP generation
/internal/shared/protocol → Tipos compartidos (request/response)
/configs → systemd service
/scripts → Instalación cliente/servidor
```

## Archivos clave
| Archivo | Rol | Se modifica frecuentemente |
|---------|-----|---------------------------|
| cmd/zcloud/main.go | CLI entry point, todos los comandos | sí |
| cmd/zcloud-server/main.go | Server entry point, config loading | no |
| internal/server/api/handlers.go | HTTP handlers principales | sí |
| internal/server/middleware/auth.go | JWT validation, token revocation | sí |
| internal/server/db/database.go | SQLite operations | sí |
| internal/client/auth.go | Device registration, login flow | no |
| internal/shared/protocol/types.go | Shared structs (protocolo) | raramente |

## Dependencias entre módulos
client → shared/protocol + shared/crypto
server/api → server/db + shared/protocol + shared/crypto
server/middleware → server/db (para token revocation)

## Convenciones
- Naming: PascalCase para exportado, camelCase JSON tags
- Estado: SQLite para persistencia, JWT en memoria con blacklist
- Errores: fmt.Errorf con wrapping, http.Error para respuestas
- Imports: stdlib, luego externas, luego internas (sección vacía entre)

## Comandos
| Comando | Qué hace |
|---------|----------|
| `make build` | Compila cliente y servidor (linux amd64/arm64) |
| `make test` | Ejecuta tests (`go test -v ./...`) |
| `make dev-server` | Servidor con config de desarrollo |
| `zcloud init <url>` | Registra dispositivo en servidor |
| `zcloud start` | Login con TOTP, genera kubeconfig |
| `zcloud-server --init` | Inicializa servidor (crea config, DB, secret) |
| `zcloud-server admin devices <list|approve|revoke>` | Admin CLI directo |
