# zcloud

Secure remote access to Kubernetes clusters through a small client and a
self-hosted server. zcloud keeps the Kubernetes API private while exposing the
operations you choose through an authenticated HTTPS endpoint.

The server can run on any Linux host that can reach the Kubernetes API. The
cluster may be k3s, kubeadm, a managed distribution, or another conforming
Kubernetes installation.

## How it works

```text
  zcloud client                 zcloud-server                 Kubernetes API
  ------------------ HTTPS ---- ------------------             --------------
  device key + TOTP             JWT sessions                    active kubeconfig
  kubectl-compatible proxy      device administration            token/cert auth
```

The client stores an Ed25519 device key and a short-lived session locally. The
server reads one configured kubeconfig, authenticates to its active context,
and proxies Kubernetes API traffic without exposing the cluster endpoint to the
client.

## Features

- Kubernetes API proxy compatible with `kubectl`, Helm, watches, exec, logs,
  and port-forward.
- Apply manifests, execute an allow-listed command set, transfer files, and
  open an SSH shell through the authenticated session.
- Device registration and approval, per-user TOTP enrollment, JWT sessions,
  token revocation, rate limiting, security headers, and audit logging.
- Linux binaries for `amd64` and `arm64`, published as GitHub release assets.
- No database or third-party control plane is required: the server uses SQLite
  and the Kubernetes credentials already present on the host.

## Requirements

Server:

- Linux `amd64` or `arm64` host with systemd for the packaged installer.
- Network access to the Kubernetes API from that host.
- A kubeconfig with an active context and either a bearer token or client
  certificate credentials. The API server URL is read from that context.
- A DNS name and a trusted TLS certificate for production use.

Client:

- Linux `amd64` or `arm64`.
- `curl` or `wget` for the installer and an authenticator application for TOTP.
- `kubectl` is needed only when using the generated kubeconfig directly.

Building from source requires Go 1.22 or newer. The prebuilt installers do not
require Go.

## Installation

### Server: automated

The first server install is bootstrapped from the repository. Set the public
hostname and kubeconfig explicitly so the command is non-interactive:

```bash
curl -fsSL https://raw.githubusercontent.com/Zyrakk/zcloud/main/scripts/install-server.sh \
  | sudo env \
      ZCLOUD_API_DOMAIN=k8s.example.com \
      ZCLOUD_KUBECONFIG=/etc/kubernetes/admin.conf \
      bash
```

The installer downloads the matching release binary, verifies its SHA-256
checksum, creates `/opt/zcloud-server/`, writes a systemd unit, and initializes
the database. It does not overwrite an existing configuration or certificates.
Review `/opt/zcloud-server/config.yaml`, provision TLS, and then start it:

```bash
sudo certbot certonly --standalone -d k8s.example.com
sudo ln -sf /etc/letsencrypt/live/k8s.example.com/fullchain.pem \
  /opt/zcloud-server/certs/fullchain.pem
sudo ln -sf /etc/letsencrypt/live/k8s.example.com/privkey.pem \
  /opt/zcloud-server/certs/privkey.pem
sudo systemctl enable --now zcloud-server
curl --fail https://k8s.example.com/health
```

Set `ZCLOUD_VERSION=v2.2.1` to pin a release. `ZCLOUD_INSTALL_DIR` can be used
for a different installation path. The installer detects common k3s and
kubeadm kubeconfig locations when `ZCLOUD_KUBECONFIG` is omitted.

### Server: from source

```bash
git clone https://github.com/Zyrakk/zcloud.git
cd zcloud
make build-server
make install-server
sudo /opt/zcloud-server/zcloud-server --init \
  --config /opt/zcloud-server/config.yaml
```

Edit the generated configuration before starting the service. `make install-server`
installs the binary and the systemd unit but does not create TLS certificates.

### Client

Once the server is running, the server itself publishes the installer at
`/install.sh`:

```bash
curl -fsSL https://k8s.example.com/install.sh | bash
zcloud init https://k8s.example.com
```

The script detects the architecture, downloads the client release, verifies its
checksum, and installs `/usr/local/bin/zcloud`. For a private fork or a pinned
version:

```bash
curl -fsSL https://k8s.example.com/install.sh \
  | ZCLOUD_REPO=your-org/your-repo ZCLOUD_VERSION=v2.2.1 bash
```

The equivalent source build is:

```bash
git clone https://github.com/Zyrakk/zcloud.git
cd zcloud
make build-client
make install-client
```

## First device and administrator setup

Approval is enabled by default. The first device is bootstrapped locally on the
server; later approvals can be performed by an administrator session.

1. Register the client and note the device ID:

   ```bash
   zcloud init https://k8s.example.com
   ```

2. On the server, approve the device and assign it to a user/persona. The
   command prints a one-time enrollment code valid for about ten minutes:

   ```bash
   sudo /opt/zcloud-server/zcloud-server admin devices approve <device-id> \
     --user alice --config /opt/zcloud-server/config.yaml
   ```

3. Grant administrator access to the first device only:

   ```bash
   sudo /opt/zcloud-server/zcloud-server admin devices make-admin <device-id> \
     --config /opt/zcloud-server/config.yaml
   ```

4. Complete registration and configure TOTP on the client:

   ```bash
   zcloud init --complete
   zcloud totp <enrollment-code>
   zcloud login
   ```

TOTP is associated with the user/persona, so multiple approved devices can use
the same authenticator. Rotate it when necessary:

```bash
sudo /opt/zcloud-server/zcloud-server admin users rotate alice \
  --device <device-id> --config /opt/zcloud-server/config.yaml
zcloud totp <new-enrollment-code>
```

## Daily use

```bash
zcloud login                    # start or renew the session
zcloud status                   # session and cluster status
zcloud k get pods -A            # run kubectl through the proxy
zcloud apply ./deployment.yaml  # apply a manifest or directory
zcloud exec kubectl -- get nodes
zcloud port-forward svc/api 8080:80
zcloud logout
```

`zcloud login` writes a short-lived kubeconfig to `~/.zcloud/kubeconfig`. To
use standard Kubernetes tooling directly:

```bash
export KUBECONFIG="$HOME/.zcloud/kubeconfig:$KUBECONFIG"
kubectl get nodes
helm list --all-namespaces
```

Administrative commands are available from a client with an administrator
session:

```bash
zcloud admin devices list
zcloud admin devices approve <device-id> --user bob
zcloud admin devices revoke <device-id>
```

## Configuration

The default file is `/opt/zcloud-server/config.yaml`:

```yaml
server:
  host: 0.0.0.0
  port: 443
  domain: k8s.example.com

tls:
  cert: /opt/zcloud-server/certs/fullchain.pem
  key: /opt/zcloud-server/certs/privkey.pem

auth:
  jwt_secret_file: /opt/zcloud-server/data/jwt.secret
  session_ttl: 12h
  totp_issuer: zcloud
  require_approval: true

kubernetes:
  kubeconfig: /etc/kubernetes/admin.conf
  ca_cert: /etc/kubernetes/pki/ca.crt
  coredns_ip: 10.43.0.10:53

storage:
  database: /opt/zcloud-server/data/zcloud.db
  base_file_dir: /opt/zcloud-server/files
```

`kubernetes.kubeconfig` may point to any supported distribution. zcloud uses the
active context's API server URL and credentials; it does not assume a local
`127.0.0.1:6443` endpoint. `ca_cert` is optional when the active kubeconfig
contains `certificate-authority-data`. Set `coredns_ip` to the DNS service
address used by the cluster when using service-name port forwarding.

For a reverse proxy, bind zcloud-server to an internal port such as `8443` and
forward WebSocket and HTTP/1.1 upgrade headers. The proxy must preserve the
original `Host` and `X-Forwarded-Proto` headers. Direct TLS on port 443 is also
supported.

## Health and API

```bash
curl https://k8s.example.com/health  # liveness
curl https://k8s.example.com/ready   # database and Kubernetes readiness
```

Public bootstrap routes are `GET /install.sh`, `GET /install-client.sh`, and
`GET /install-server.sh`. The API is rooted at `/api/v1` and includes device
registration, authentication, administration, manifest apply, file transfer,
SSH, and the Kubernetes proxy.

## Updates

The installers are version-aware and can be rerun with a pinned release. For a
source deployment, build first and replace the binary atomically:

```bash
make build-client
sudo install -m 0755 dist/zcloud-linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
  /usr/local/bin/zcloud

make build-server
sudo install -m 0755 dist/zcloud-server-linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
  /opt/zcloud-server/zcloud-server
sudo systemctl restart zcloud-server
```

Always run `zcloud version`, `zcloud-server --version`, and the health checks
after an update. Back up `/opt/zcloud-server/data/` before replacing a server
binary or migrating a database.

### Publishing a release

Releases are published by GitHub Actions. After merging the changes for a
version, create and push a semantic-version tag:

```bash
git tag v2.3.0
git push origin v2.3.0
```

The release workflow runs the tests, builds the client and server for `amd64`
and `arm64`, creates `checksums-sha256.txt`, uploads all artifacts, and
generates the release notes from commits and pull requests. Do not build or
upload release files manually.

## Development and tests

```bash
make deps
make test
make build
```

Use `make dev-server` with `configs/dev-config.yaml` for local development.
Never commit a development configuration containing cluster credentials or
private keys.

## Security notes

- Use a publicly trusted TLS certificate in production; do not disable client
  certificate verification to work around a configuration error.
- Restrict access to the server configuration, JWT secret, SQLite database,
  kubeconfig, and `~/.zcloud/device.key`.
- The installer verifies release checksums. `ZCLOUD_SKIP_VERIFY=1` is an
  explicit opt-out for controlled environments and should not be used by
  default.
- `/api/v1/k8s/proxy/*` still requires a zcloud session even though it is not
  rate-limited, which allows Helm and watch operations to make parallel calls.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Contributing

Bug reports and pull requests are welcome. Keep changes focused, add tests for
security-sensitive behavior, and run `make test` before submitting a pull
request.
