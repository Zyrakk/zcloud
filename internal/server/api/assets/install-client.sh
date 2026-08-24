#!/usr/bin/env bash
# Install the zcloud client from a published GitHub release.
#
# Usage:
#   curl -fsSL https://your-zcloud-server.example.com/install.sh | bash
#
# Optional environment variables:
#   ZCLOUD_REPO          GitHub repository (default: Zyrakk/zcloud)
#   ZCLOUD_VERSION       release tag or version (default: latest)
#   ZCLOUD_INSTALL_DIR   destination directory (default: /usr/local/bin)
#   ZCLOUD_SKIP_VERIFY   set to 1 only when checksum verification is unavailable

set -euo pipefail

REPO="${ZCLOUD_REPO:-Zyrakk/zcloud}"
VERSION="${ZCLOUD_VERSION:-latest}"
INSTALL_DIR="${ZCLOUD_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="zcloud"

log() { printf '[zcloud] %s\n' "$*"; }
die() { printf '[zcloud] Error: %s\n' "$*" >&2; exit 1; }

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

install_binary() {
    local source="$1"
    local target="$INSTALL_DIR/$BINARY_NAME"

    if [ -d "$INSTALL_DIR" ] && [ -w "$INSTALL_DIR" ]; then
        install -m 0755 "$source" "$target"
        return
    fi

    command -v sudo >/dev/null 2>&1 || die "$INSTALL_DIR is not writable and sudo is unavailable"
    sudo mkdir -p "$INSTALL_DIR"
    sudo install -m 0755 "$source" "$target"
}

main() {
    [ "$(uname -s)" = Linux ] || die "only Linux is currently supported"

    local arch binary release_base tmp_dir checksum_file expected_checksum
    arch="$(detect_arch)"
    binary="zcloud-linux-$arch"
    release_base="https://github.com/$REPO/releases/$(release_path)"
    tmp_dir="$(mktemp -d)"
    checksum_file="$tmp_dir/checksums-sha256.txt"
    trap "rm -rf '$tmp_dir'" EXIT

    log "Downloading $binary ($VERSION)"
    download "$release_base/$binary" "$tmp_dir/$binary"

    if [ "${ZCLOUD_SKIP_VERIFY:-0}" != 1 ]; then
        command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required for checksum verification (or set ZCLOUD_SKIP_VERIFY=1)"
        download "$release_base/checksums-sha256.txt" "$checksum_file"
        expected_checksum="$(awk -v name="$binary" '$2 == name { print $1; exit }' "$checksum_file")"
        [ -n "$expected_checksum" ] || die "no checksum found for $binary"
        printf '%s  %s\n' "$expected_checksum" "$tmp_dir/$binary" | sha256sum -c - >/dev/null \
            || die "checksum verification failed"
    fi

    install_binary "$tmp_dir/$binary"
    log "Installed $INSTALL_DIR/$BINARY_NAME"
    "$INSTALL_DIR/$BINARY_NAME" version 2>/dev/null || true
    log "Initialize it with: zcloud init https://your-zcloud-server.example.com"
}

main "$@"
