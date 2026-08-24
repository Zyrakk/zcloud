package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyrak/zcloud/internal/server/db"
)

func TestInstallScriptsArePublic(t *testing.T) {
	database, err := db.New(filepath.Join(t.TempDir(), "zcloud.db"))
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	defer database.Close()

	server := New(database, &Config{JWTSecret: "test-secret", CORSOrigin: "example.com"})
	defer server.Close()
	handler := server.Router()

	for _, path := range []string{"/install.sh", "/install-client.sh", "/install-server.sh"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
			if !strings.HasPrefix(response.Body.String(), "#!/usr/bin/env bash\n") {
				t.Fatal("response does not contain a bash installer")
			}
			if got := response.Header().Get("Cache-Control"); got != "no-cache" {
				t.Errorf("Cache-Control = %q, want no-cache", got)
			}
		})
	}
}
