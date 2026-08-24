# ZCloud v2.3.1

Curated release notes are now published together with every automated build.
GitHub Actions remains responsible for testing, compiling, checksumming, and
uploading the artifacts, while this file keeps the operational guidance and
compatibility notes explicit.

## Highlights

- GitHub Actions publishes non-draft releases when a `v*` tag is pushed.
- Release notes are taken from `RELEASE_NOTES.md` instead of a generic commit
  summary.
- The workflow publishes client and server binaries for Linux `amd64` and
  `arm64`, plus `checksums-sha256.txt`.
- The public client installer verifies the downloaded release checksum before
  installing it.

## Compatibility

- No breaking changes to the client or server API.
- Existing zcloud client configurations and sessions remain compatible.
- The Kubernetes proxy continues to support normal API requests, watches,
  logs, `kubectl exec`, and `kubectl port-forward`.

## Upgrade

### Server

Run the installer on the Linux host that runs `zcloud-server`. Set the public
hostname and kubeconfig for a new installation; an existing configuration is
preserved by the installer.

```bash
curl -fsSL https://your-zcloud-server.example.com/install-server.sh \
  | sudo env \
      ZCLOUD_VERSION=v2.3.1 \
      ZCLOUD_API_DOMAIN=your-zcloud-server.example.com \
      ZCLOUD_KUBECONFIG=/path/to/kubeconfig \
      bash
sudo systemctl restart zcloud-server
sudo systemctl status zcloud-server --no-pager
```

For a source installation:

```bash
git pull
make build-server VERSION=2.3.1
sudo install -m 0755 dist/zcloud-server-linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
  /opt/zcloud-server/zcloud-server
sudo systemctl restart zcloud-server
```

### Client

```bash
curl -fsSL https://your-zcloud-server.example.com/install.sh \
  | ZCLOUD_VERSION=v2.3.1 bash
zcloud version
```

The client update does not remove `~/.zcloud/config.yaml`, device keys, or the
generated kubeconfig.

## Verification

```bash
zcloud version
zcloud status
curl --fail https://your-zcloud-server.example.com/health
curl --fail https://your-zcloud-server.example.com/ready

export KUBECONFIG="$HOME/.zcloud/kubeconfig"
kubectl get pods -A
kubectl exec <pod> -- ls /
kubectl logs -f <pod>
kubectl port-forward pod/<pod> 8080:80
helm list --all-namespaces
```

## Artifacts

| File | Description |
|------|-------------|
| `zcloud-server-linux-amd64` | Server for Linux x86-64 |
| `zcloud-server-linux-arm64` | Server for Linux ARM64 |
| `zcloud-linux-amd64` | Client for Linux x86-64 |
| `zcloud-linux-arm64` | Client for Linux ARM64 |
| `checksums-sha256.txt` | SHA-256 checksums for all binaries |
