package api

import (
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"strings"
)

// handleK8sProxy proxies requests to the local Kubernetes API
func (a *API) handleK8sProxy(w http.ResponseWriter, r *http.Request) {
	// Extract the path after /api/v1/k8s/proxy/
	// Example: /api/v1/k8s/proxy/api/v1/pods → /api/v1/pods
	k8sPath := strings.TrimPrefix(r.URL.Path, "/api/v1/k8s/proxy")
	if k8sPath == "" {
		k8sPath = "/"
	}

	// Build the target URL for k3s API
	k8sURL := "https://127.0.0.1:6443" + k8sPath
	if r.URL.RawQuery != "" {
		k8sURL += "?" + r.URL.RawQuery
	}

	// Create the proxy request
	proxyReq, err := http.NewRequest(r.Method, k8sURL, r.Body)
	if err != nil {
		http.Error(w, "failed to create proxy request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy relevant headers from original request
	for key, values := range r.Header {
		// Skip hop-by-hop headers
		if key == "Connection" || key == "Keep-Alive" || key == "Proxy-Authenticate" ||
			key == "Proxy-Authorization" || key == "Te" || key == "Trailers" ||
			key == "Transfer-Encoding" || key == "Upgrade" {
			continue
		}
		// Skip Authorization - we'll use k8s service account token instead
		if key == "Authorization" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Use k3s service account token for authentication
	// First try the in-cluster service account token
	k8sToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		// Fallback to kubeconfig token if not running in-cluster
		k8sToken, err = getKubeconfigToken(a.config.KubeconfigPath)
		if err != nil {
			http.Error(w, "failed to get k8s token: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	proxyReq.Header.Set("Authorization", "Bearer "+string(k8sToken))

	// Create HTTP client with TLS skip verify (for self-signed k3s certs)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Execute the request
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "failed to proxy request: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}

// getKubeconfigToken extracts the token from a kubeconfig file
func getKubeconfigToken(kubeconfigPath string) ([]byte, error) {
	// For server-side, we typically use a dedicated service account or admin config
	// This is a fallback when not running in-cluster
	data, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		return nil, err
	}

	// Simple token extraction - look for "token:" in the file
	// In production, you'd want proper YAML parsing
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "token:") {
			token := strings.TrimPrefix(line, "token:")
			token = strings.TrimSpace(token)
			token = strings.Trim(token, "\"'")
			return []byte(token), nil
		}
	}

	return nil, os.ErrNotExist
}
