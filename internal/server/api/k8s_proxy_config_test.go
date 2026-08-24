package api

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestActiveKubeconfigEntries(t *testing.T) {
	data := []byte(`
clusters:
  - name: ignored-cluster
    cluster:
      server: https://ignored.example.com
  - name: active-cluster
    cluster:
      server: https://kubernetes.example.com:6443
users:
  - name: ignored-user
    user:
      token: ignored
  - name: active-user
    user:
      token: active-token
contexts:
  - name: ignored
    context:
      cluster: ignored-cluster
      user: ignored-user
  - name: active
    context:
      cluster: active-cluster
      user: active-user
current-context: active
`)

	var config kubeconfigFile
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("parse kubeconfig: %v", err)
	}

	cluster, user, err := activeKubeconfigEntries(&config)
	if err != nil {
		t.Fatalf("find active entries: %v", err)
	}
	if cluster.Name != "active-cluster" || cluster.Cluster.Server != "https://kubernetes.example.com:6443" {
		t.Errorf("unexpected cluster: %#v", cluster)
	}
	if user.Name != "active-user" || user.User.Token != "active-token" {
		t.Errorf("unexpected user: %#v", user)
	}
}

func TestDecodeOrReadKubeconfigData(t *testing.T) {
	dir := t.TempDir()
	fileData := []byte("certificate data")
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), fileData, 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	fromFile, err := decodeOrReadKubeconfigData("", "ca.crt", dir)
	if err != nil {
		t.Fatalf("read relative file: %v", err)
	}
	if string(fromFile) != string(fileData) {
		t.Errorf("file data = %q, want %q", fromFile, fileData)
	}

	inline := base64.StdEncoding.EncodeToString([]byte("inline data"))
	fromInline, err := decodeOrReadKubeconfigData(inline, "missing.crt", dir)
	if err != nil {
		t.Fatalf("decode inline data: %v", err)
	}
	if string(fromInline) != "inline data" {
		t.Errorf("inline data = %q, want inline data", fromInline)
	}
}
