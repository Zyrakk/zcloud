package api

import (
	_ "embed"
	"net/http"
)

// These scripts are embedded so a server installation can bootstrap clients
// without requiring a separate web server or a host-specific document root.
// Keep the copies in scripts/ and internal/server/api/assets/ synchronized.
//
//go:embed assets/install-client.sh
var installClientScript []byte

//go:embed assets/install-server.sh
var installServerScript []byte

func serveInstallScript(script []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(script)
	}
}
