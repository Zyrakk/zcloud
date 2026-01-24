package api

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// kubeconfig structures for parsing k3s.yaml
type kubeconfigFile struct {
	Clusters []struct {
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
			Token                 string `yaml:"token"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// handleK8sProxy proxies requests to the local Kubernetes API
func (a *API) handleK8sProxy(w http.ResponseWriter, r *http.Request) {
	// Extract the path after /api/v1/k8s/proxy/
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
		// Skip Authorization - we'll use k8s credentials
		if key == "Authorization" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Get k8s client from kubeconfig
	client, err := a.getK8sClient()
	if err != nil {
		http.Error(w, "failed to get k8s credentials: "+err.Error(), http.StatusInternalServerError)
		return
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

// getK8sClient creates an HTTP client with k3s credentials from kubeconfig
func (a *API) getK8sClient() (*http.Client, error) {
	// Read and parse kubeconfig
	data, err := os.ReadFile(a.config.KubeconfigPath)
	if err != nil {
		return nil, err
	}

	var kc kubeconfigFile
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, err
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // k3s uses self-signed certs
	}

	// Check if we have client certificate auth
	if len(kc.Users) > 0 && kc.Users[0].User.ClientCertificateData != "" {
		certData, err := base64.StdEncoding.DecodeString(kc.Users[0].User.ClientCertificateData)
		if err != nil {
			return nil, err
		}
		keyData, err := base64.StdEncoding.DecodeString(kc.Users[0].User.ClientKeyData)
		if err != nil {
			return nil, err
		}

		cert, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

