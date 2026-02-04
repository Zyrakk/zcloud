package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// k8sClientConfig caches the TLS config to avoid re-parsing kubeconfig
var (
	k8sConfigOnce  sync.Once
	k8sConfigErr   error
	k8sCACertPool  *x509.CertPool
	k8sClientCert  tls.Certificate
	k8sHasClientCert bool
	k8sBearerToken string
)

// kubeconfigFile represents the structure of a kubeconfig file
type kubeconfigFile struct {
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
			Token                 string `yaml:"token"`
		} `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	CurrentContext string `yaml:"current-context"`
}

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

	// Check if this is a streaming request (requires flushing + no timeout)
	isStream := isStreamingRequest(r)

	// Create the proxy request with context propagation for cancellation.
	// For non-streaming requests, enforce a reasonable timeout to avoid hanging handlers.
	ctx := r.Context()
	if !isStream {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
	}

	proxyReq, err := http.NewRequestWithContext(ctx, r.Method, k8sURL, r.Body)
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
		// Skip Authorization - we'll use k8s credentials from kubeconfig
		if key == "Authorization" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Get or create HTTP client with proper authentication
	client, token, err := a.getK8sClient()
	if err != nil {
		http.Error(w, "failed to create k8s client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// If we have a token (instead of client certs), add it to the header
	if token != "" {
		proxyReq.Header.Set("Authorization", "Bearer "+token)
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

	// Copy response body with streaming support for watch requests
	if isStream {
		// Use flushing copy for streaming requests
		flushingCopy(w, resp.Body)
	} else {
		// Standard copy for regular requests
		io.Copy(w, resp.Body)
	}
}

// getK8sClient creates an HTTP client with proper TLS configuration for k8s auth
// It caches the TLS config but creates a new client for each request to avoid connection reuse issues
func (a *API) getK8sClient() (*http.Client, string, error) {
	k8sConfigOnce.Do(func() {
		// Load CA certificate if specified in config
		if a.config.CACertPath != "" {
			certData, err := os.ReadFile(a.config.CACertPath)
			if err != nil {
				log.Printf("Failed to read CA certificate: %v", err)
				k8sConfigErr = err
				return
			}

			// Create certificate pool with CA
			k8sCACertPool = x509.NewCertPool()
			if !k8sCACertPool.AppendCertsFromPEM(certData) {
				log.Printf("Failed to parse CA certificate")
				k8sConfigErr = err
				return
			}
		}

		// First try in-cluster service account token
		tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err == nil {
			// Running in-cluster - use service account token.
			k8sBearerToken = strings.TrimSpace(string(tokenBytes))
			k8sHasClientCert = false

			// If no CA was specified, use the in-cluster service account CA if present.
			if k8sCACertPool == nil {
				if caBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"); err == nil {
					caPool := x509.NewCertPool()
					if caPool.AppendCertsFromPEM(caBytes) {
						k8sCACertPool = caPool
					}
				}
			}
			return
		}

		// Not in-cluster - parse kubeconfig
		kubeconfigPath := a.config.KubeconfigPath
		if kubeconfigPath == "" {
			k8sConfigErr = os.ErrNotExist
			return
		}

		data, err := os.ReadFile(kubeconfigPath)
		if err != nil {
			k8sConfigErr = err
			return
		}

		var kubeconfig kubeconfigFile
		if err := yaml.Unmarshal(data, &kubeconfig); err != nil {
			k8sConfigErr = err
			return
		}

		// Find current context's user
		var currentUser string
		for _, ctx := range kubeconfig.Contexts {
			if ctx.Name == kubeconfig.CurrentContext {
				currentUser = ctx.Context.User
				break
			}
		}

		// Find user credentials
		for _, user := range kubeconfig.Users {
			if user.Name == currentUser {
				// Check if user has token (some kubeconfigs use token auth)
				if user.User.Token != "" {
					k8sBearerToken = strings.TrimSpace(user.User.Token)
					k8sHasClientCert = false
					return
				}

				// Use client certificate authentication (k3s default)
				if user.User.ClientCertificateData != "" && user.User.ClientKeyData != "" {
					certData, err := base64.StdEncoding.DecodeString(user.User.ClientCertificateData)
					if err != nil {
						k8sConfigErr = err
						return
					}

					keyData, err := base64.StdEncoding.DecodeString(user.User.ClientKeyData)
					if err != nil {
						k8sConfigErr = err
						return
					}

					cert, err := tls.X509KeyPair(certData, keyData)
					if err != nil {
						k8sConfigErr = err
						return
					}

					k8sClientCert = cert
					k8sHasClientCert = true

					// Try to load CA from kubeconfig if not specified in server config
					if k8sCACertPool == nil {
						for _, cluster := range kubeconfig.Clusters {
							if cluster.Cluster.CertificateAuthorityData != "" {
								caData, err := base64.StdEncoding.DecodeString(cluster.Cluster.CertificateAuthorityData)
								if err == nil {
									caPool := x509.NewCertPool()
									if caPool.AppendCertsFromPEM(caData) {
										k8sCACertPool = caPool
										break
									}
								}
							}
						}
					}
					return
				}
			}
		}

		k8sConfigErr = os.ErrNotExist
	})

	if k8sConfigErr != nil {
		return nil, "", k8sConfigErr
	}

	// Create a new HTTP client for each request with fresh TLS config
	tlsConfig := &tls.Config{InsecureSkipVerify: false}
	if k8sCACertPool != nil {
		tlsConfig.RootCAs = k8sCACertPool
	}
	if k8sHasClientCert {
		tlsConfig.Certificates = []tls.Certificate{k8sClientCert}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			// Disable HTTP/2 to avoid connection reuse issues with Helm
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			// Use shorter idle timeout to avoid stale connections
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		},
		// Timeout is controlled per-request via context in handleK8sProxy.
		Timeout: 0,
	}

	return client, k8sBearerToken, nil
}

// isStreamingRequest checks if the request should be treated as a long-lived stream.
func isStreamingRequest(r *http.Request) bool {
	q := r.URL.Query()
	if q.Get("watch") == "true" {
		return true
	}
	if q.Get("follow") == "true" {
		// kubectl logs -f
		return true
	}
	return false
}

// flushingCopy copies data from src to dst, flushing after each chunk
// This is required for HTTP/2 streaming to work correctly with kubectl watch
func flushingCopy(dst http.ResponseWriter, src io.Reader) error {
	flusher, canFlush := dst.(http.Flusher)
	buf := make([]byte, 32*1024) // 32KB buffer

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			_, writeErr := dst.Write(buf[:n])
			if writeErr != nil {
				return writeErr
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
