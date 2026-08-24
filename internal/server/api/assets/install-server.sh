#!/usr/bin/env bash
# Install zcloud-server on a Linux host with access to a Kubernetes cluster.
#
# Usage:
#   curl -fsSL https://your-zcloud-server.example.com/install-server.sh | sudo bash
#
# Set these variables for a non-interactive installation:
#   ZCLOUD_API_DOMAIN, ZCLOUD_SERVER_PORT, ZCLOUD_KUBECONFIG,
#   ZCLOUD_CA_CERT, ZCLOUD_VERSION, ZCLOUD_INSTALL_DIR

set -euo pipefail

INSTALL_DIR="${ZCLOUD_INSTALL_DIR:-/opt/zcloud-server}"
DATA_DIR="$INSTALL_DIR/data"
CERT_DIR="$INSTALL_DIR/certs"
REPO="${ZCLOUD_REPO:-Zyrakk/zcloud}"
VERSION="${ZCLOUD_VERSION:-latest}"
API_DOMAIN="${ZCLOUD_API_DOMAIN:-}"
SERVER_PORT="${ZCLOUD_SERVER_PORT:-443}"
KUBECONFIG_PATH="${ZCLOUD_KUBECONFIG:-}"
CA_CERT_PATH="${ZCLOUD_CA_CERT:-}"
CONFIG_PATH="$INSTALL_DIR/config.yaml"

log() { printf '[zcloud-server] %s\n' "$*"; }
warn() { printf '[zcloud-server] Warning: %s\n' "$*" >&2; }
die() { printf '[zcloud-server] Error: %s\n' "$*" >&2; exit 1; }

download() {
    local url="$1"
    local destination="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 1 -o "$destination" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$destination" "$url"
    else
        die "curl or wget is required"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64) echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

release_path() {
    case "$VERSION" in
        latest|"") echo latest/download ;;
        v*) echo "download/$VERSION" ;;
        *) echo "download/v$VERSION" ;;
    esac
}

find_kubeconfig() {
    if [ -n "$KUBECONFIG_PATH" ]; then
        return
    fi

    local candidate
    for candidate in \
        /etc/rancher/k3s/k3s.yaml \
        /etc/kubernetes/admin.conf \
        /root/.kube/config; do
        if [ -f "$candidate" ]; then
            KUBECONFIG_PATH="$candidate"
            return
        fi
    done

    KUBECONFIG_PATH="/etc/kubernetes/admin.conf"
    warn "no kubeconfig was found; update $CONFIG_PATH before starting the service"
}

find_ca_cert() {
    [ -n "$CA_CERT_PATH" ] && return

    local candidate
    for candidate in \
        /var/lib/rancher/k3s/server/tls/server-ca.crt \
        /etc/kubernetes/pki/ca.crt; do
        if [ -f "$candidate" ]; then
            CA_CERT_PATH="$candidate"
            return
        fi
    done
}

install_binary() {
    local arch="$1"
    local binary="zcloud-server-linux-$arch"
    local tmp_dir="$2"
    local script_dir local_binary
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || true)"
    local_binary="${script_dir:+$script_dir/dist/$binary}"

    if [ -n "$local_binary" ] && [ -f "$local_binary" ]; then
        install -m 0755 "$local_binary" "$INSTALL_DIR/zcloud-server"
        log "Installed local build $local_binary"
        return
    fi

    local release_base="https://github.com/$REPO/releases/$(release_path)"
    log "Downloading $binary ($VERSION)"
    download "$release_base/$binary" "$tmp_dir/$binary"

    command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required for checksum verification"
    download "$release_base/checksums-sha256.txt" "$tmp_dir/checksums-sha256.txt"
    local expected_checksum
    expected_checksum="$(awk -v name="$binary" '$2 == name { print $1; exit }' "$tmp_dir/checksums-sha256.txt")"
    [ -n "$expected_checksum" ] || die "no checksum found for $binary"
    printf '%s  %s\n' "$expected_checksum" "$tmp_dir/$binary" | sha256sum -c - >/dev/null \
        || die "checksum verification failed"

    install -m 0755 "$tmp_dir/$binary" "$INSTALL_DIR/zcloud-server"
}

create_config() {
    [ -f "$CONFIG_PATH" ] && { log "Keeping existing $CONFIG_PATH"; return; }

    if [ -z "$API_DOMAIN" ] && [ -t 0 ]; then
        read -r -p 'Public API hostname (for example, zcloud.example.com): ' API_DOMAIN
    fi
    API_DOMAIN="${API_DOMAIN:-localhost}"
    find_kubeconfig
    find_ca_cert

    cat > "$CONFIG_PATH" <<EOF
# zcloud-server configuration
server:
  host: 0.0.0.0
  port: $SERVER_PORT
  domain: $API_DOMAIN

tls:
  cert: $CERT_DIR/fullchain.pem
  key: $CERT_DIR/privkey.pem
  auto_renew: true

auth:
  jwt_secret_file: $DATA_DIR/jwt.secret
  session_ttl: 12h
  totp_issuer: zcloud
  require_approval: true

kubernetes:
  kubeconfig: $KUBECONFIG_PATH
  coredns_ip: 10.43.0.10:53
  ca_cert: $CA_CERT_PATH

storage:
  database: $DATA_DIR/zcloud.db
  base_file_dir: $INSTALL_DIR/files
EOF
    chmod 0600 "$CONFIG_PATH"
}

install_systemd_unit() {
    command -v systemctl >/dev/null 2>&1 || die "systemd is required to install the service"

    cat > /etc/systemd/system/zcloud-server.service <<EOF
[Unit]
Description=zcloud Kubernetes management server
Documentation=https://github.com/$REPO
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$INSTALL_DIR/zcloud-server --config $CONFIG_PATH
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zcloud-server
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $INSTALL_DIR/files
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

configure_firewall() {
    if command -v ufw >/dev/null 2>&1; then
        ufw allow "$SERVER_PORT/tcp" comment 'zcloud API' >/dev/null || true
        log "Allowed TCP port $SERVER_PORT in UFW"
    else
        warn "configure TCP port $SERVER_PORT in the host or cloud firewall"
    fi
}

print_next_steps() {
    local domain
    domain="$(awk '/^[[:space:]]*domain:/ {print $2; exit}' "$CONFIG_PATH")"

    cat <<EOF

zcloud-server is installed in $INSTALL_DIR.

Before starting it:
  1. Point DNS for $domain to this host.
  2. Provision TLS certificates:
       certbot certonly --standalone -d $domain
       ln -sf /etc/letsencrypt/live/$domain/fullchain.pem $CERT_DIR/fullchain.pem
       ln -sf /etc/letsencrypt/live/$domain/privkey.pem $CERT_DIR/privkey.pem
  3. Confirm the Kubernetes paths in $CONFIG_PATH.
  4. Start the service:
       systemctl enable --now zcloud-server

Health check: curl https://$domain/health
Logs:         journalctl -u zcloud-server -f
EOF
}

main() {
    [ "$(id -u)" -eq 0 ] || die "run this installer as root (for example, curl ... | sudo bash)"
    command -v install >/dev/null 2>&1 || die "the install command is required"

    local arch tmp_dir
    arch="$(detect_arch)"
    tmp_dir="$(mktemp -d)"
    trap "rm -rf '$tmp_dir'" EXIT

    mkdir -p "$DATA_DIR" "$CERT_DIR" "$INSTALL_DIR/files"
    chmod 0750 "$INSTALL_DIR" "$CERT_DIR"
    chmod 0700 "$DATA_DIR"
    install_binary "$arch" "$tmp_dir"
    create_config

    "$INSTALL_DIR/zcloud-server" --init --config "$CONFIG_PATH"
    install_systemd_unit
    configure_firewall
    print_next_steps
}

main "$@"
