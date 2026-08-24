package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// k8sClientConfig caches the TLS config AND the HTTP client (singleton)
var (
	k8sConfigOnce    sync.Once
	k8sConfigErr     error
	k8sCACertPool    *x509.CertPool
	k8sClientCert    tls.Certificate
	k8sHasClientCert bool
	k8sBearerToken   string
	k8sServerURL     string
	k8sHTTPClient    *http.Client // Singleton HTTP client with connection pooling
)

// kubeconfigFile represents the subset of kubeconfig needed by the proxy.
type kubeconfigCluster struct {
	Name    string `yaml:"name"`
	Cluster struct {
		Server                   string `yaml:"server"`
		CertificateAuthority     string `yaml:"certificate-authority"`
		CertificateAuthorityData string `yaml:"certificate-authority-data"`
		InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
	} `yaml:"cluster"`
}

type kubeconfigUser struct {
	Name string `yaml:"name"`
	User struct {
		ClientCertificate     string `yaml:"client-certificate"`
		ClientCertificateData string `yaml:"client-certificate-data"`
		ClientKey             string `yaml:"client-key"`
		ClientKeyData         string `yaml:"client-key-data"`
		Token                 string `yaml:"token"`
	} `yaml:"user"`
}

type kubeconfigContext struct {
	Name    string `yaml:"name"`
	Context struct {
		Cluster string `yaml:"cluster"`
		User    string `yaml:"user"`
	} `yaml:"context"`
}

type kubeconfigFile struct {
	Clusters       []kubeconfigCluster `yaml:"clusters"`
	Users          []kubeconfigUser    `yaml:"users"`
	Contexts       []kubeconfigContext `yaml:"contexts"`
	CurrentContext string              `yaml:"current-context"`
}

func activeKubeconfigEntries(config *kubeconfigFile) (*kubeconfigCluster, *kubeconfigUser, error) {
	var context *kubeconfigContext
	for i := range config.Contexts {
		if config.Contexts[i].Name == config.CurrentContext {
			context = &config.Contexts[i]
			break
		}
	}
	if context == nil || context.Context.User == "" || context.Context.Cluster == "" {
		return nil, nil, fmt.Errorf("current context %q is missing a user or cluster", config.CurrentContext)
	}

	var cluster *kubeconfigCluster
	for i := range config.Clusters {
		if config.Clusters[i].Name == context.Context.Cluster {
			cluster = &config.Clusters[i]
			break
		}
	}
	if cluster == nil || cluster.Cluster.Server == "" {
		return nil, nil, fmt.Errorf("cluster %q is missing a server URL", context.Context.Cluster)
	}

	var user *kubeconfigUser
	for i := range config.Users {
		if config.Users[i].Name == context.Context.User {
			user = &config.Users[i]
			break
		}
	}
	if user == nil {
		return nil, nil, fmt.Errorf("user %q was not found", context.Context.User)
	}

	return cluster, user, nil
}

func decodeOrReadKubeconfigData(inlineData, filePath, baseDir string) ([]byte, error) {
	if inlineData != "" {
		data, err := base64.StdEncoding.DecodeString(inlineData)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 data: %w", err)
		}
		return data, nil
	}
	if filePath == "" {
		return nil, nil
	}
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(baseDir, filePath)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", filePath, err)
	}
	return data, nil
}

// handleK8sProxy proxies requests to the local Kubernetes API
func (a *API) handleK8sProxy(w http.ResponseWriter, r *http.Request) {
	// Extract the path after /api/v1/k8s/proxy/
	// Example: /api/v1/k8s/proxy/api/v1/pods → /api/v1/pods
	k8sPath := strings.TrimPrefix(r.URL.Path, "/api/v1/k8s/proxy")
	if k8sPath == "" {
		k8sPath = "/"
	}

	// Initialize credentials and the API endpoint from the active kubeconfig.
	if _, _, err := a.getK8sClient(); err != nil {
		http.Error(w, "failed to create k8s client: "+err.Error(), http.StatusInternalServerError)
		return
	}
	k8sURL := strings.TrimRight(k8sServerURL, "/") + k8sPath
	if r.URL.RawQuery != "" {
		k8sURL += "?" + r.URL.RawQuery
	}

	// Protocol upgrades (SPDY/WebSocket) for kubectl exec, port-forward, etc.
	// Must be checked before streaming — upgrade requests use raw TCP tunneling.
	if isUpgradeRequest(r) {
		a.handleK8sUpgradeProxy(w, r, k8sURL)
		return
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

	// Copy relevant headers from original request.
	// Hop-by-hop headers (Connection, Upgrade, etc.) are stripped for normal requests;
	// upgrade requests are handled by handleK8sUpgradeProxy above which forwards them.
	for key, values := range r.Header {
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

	// Get the singleton HTTP client with proper authentication
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

// getK8sClient returns the singleton HTTP client with proper TLS configuration for k8s auth.
// The client is created once and reused for all requests, with a large connection pool.
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
				k8sConfigErr = fmt.Errorf("failed to parse CA certificate from %s", a.config.CACertPath)
				return
			}
		}

		// First try in-cluster service account token
		tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err == nil {
			// Running in-cluster - use service account token.
			k8sBearerToken = strings.TrimSpace(string(tokenBytes))
			k8sHasClientCert = false
			serviceHost := os.Getenv("KUBERNETES_SERVICE_HOST")
			if serviceHost == "" {
				serviceHost = "kubernetes.default.svc"
			}
			servicePort := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
			if servicePort == "" {
				servicePort = "443"
			}
			k8sServerURL = "https://" + net.JoinHostPort(serviceHost, servicePort)

			// If no CA was specified, use the in-cluster service account CA if present.
			if k8sCACertPool == nil {
				if caBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"); err == nil {
					caPool := x509.NewCertPool()
					if caPool.AppendCertsFromPEM(caBytes) {
						k8sCACertPool = caPool
					}
				}
			}
		} else {
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

			activeCluster, activeUser, err := activeKubeconfigEntries(&kubeconfig)
			if err != nil {
				k8sConfigErr = err
				return
			}
			if activeCluster.Cluster.InsecureSkipTLSVerify {
				k8sConfigErr = fmt.Errorf("cluster %q disables Kubernetes TLS verification", activeCluster.Name)
				return
			}
			parsedServer, err := url.Parse(activeCluster.Cluster.Server)
			if err != nil || parsedServer.Scheme != "https" || parsedServer.Host == "" {
				k8sConfigErr = fmt.Errorf("invalid Kubernetes server URL %q", activeCluster.Cluster.Server)
				return
			}
			k8sServerURL = strings.TrimRight(parsedServer.String(), "/")

			kubeconfigDir := filepath.Dir(kubeconfigPath)
			if k8sCACertPool == nil {
				caData, err := decodeOrReadKubeconfigData(
					activeCluster.Cluster.CertificateAuthorityData,
					activeCluster.Cluster.CertificateAuthority,
					kubeconfigDir,
				)
				if err != nil {
					k8sConfigErr = fmt.Errorf("failed to load Kubernetes CA: %w", err)
					return
				}
				if len(caData) > 0 {
					caPool := x509.NewCertPool()
					if !caPool.AppendCertsFromPEM(caData) {
						k8sConfigErr = fmt.Errorf("failed to parse Kubernetes CA for cluster %q", activeCluster.Name)
						return
					}
					k8sCACertPool = caPool
				}
			}

			if activeUser.User.Token != "" {
				k8sBearerToken = strings.TrimSpace(activeUser.User.Token)
				k8sHasClientCert = false
			} else {
				certData, certErr := decodeOrReadKubeconfigData(
					activeUser.User.ClientCertificateData,
					activeUser.User.ClientCertificate,
					kubeconfigDir,
				)
				keyData, keyErr := decodeOrReadKubeconfigData(
					activeUser.User.ClientKeyData,
					activeUser.User.ClientKey,
					kubeconfigDir,
				)
				if certErr != nil || keyErr != nil {
					k8sConfigErr = fmt.Errorf("failed to load credentials for user %q: cert=%v key=%v", activeUser.Name, certErr, keyErr)
					return
				}
				if len(certData) == 0 || len(keyData) == 0 {
					k8sConfigErr = fmt.Errorf("user %q has no supported token or client certificate credentials", activeUser.Name)
					return
				}
				cert, err := tls.X509KeyPair(certData, keyData)
				if err != nil {
					k8sConfigErr = fmt.Errorf("failed to parse credentials for user %q: %w", activeUser.Name, err)
					return
				}
				k8sClientCert = cert
				k8sHasClientCert = true
			}
			if strings.TrimSpace(k8sBearerToken) == "" && !k8sHasClientCert {
				k8sConfigErr = fmt.Errorf("user %q has empty Kubernetes credentials", activeUser.Name)
				return
			}
		}

		if k8sConfigErr != nil || k8sServerURL == "" {
			if k8sConfigErr == nil {
				k8sConfigErr = fmt.Errorf("Kubernetes API server URL is not configured")
			}
			return
		}

		// Create TLS config
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
		}
		if k8sCACertPool != nil {
			tlsConfig.RootCAs = k8sCACertPool
		}
		if k8sHasClientCert {
			tlsConfig.Certificates = []tls.Certificate{k8sClientCert}
		}

		// Create SINGLETON HTTP client with optimized connection pooling for high concurrency
		// This is the key fix: reuse connections across all requests
		k8sHTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				// Connection pooling optimized for Helm's parallel requests
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100, // Allow many idle connections to k8s API
				MaxConnsPerHost:     0,   // No limit on concurrent connections
				IdleConnTimeout:     90 * time.Second,
				// Timeouts for connection establishment
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				// Disable HTTP/2 - k8s API server handles HTTP/1.1 better for concurrent requests
				// and Helm specifically has issues with HTTP/2 connection reuse
				ForceAttemptHTTP2: false,
				TLSNextProto:      make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			},
			// Timeout is controlled per-request via context in handleK8sProxy.
			Timeout: 0,
		}

		log.Printf("K8s proxy client initialized with connection pooling (MaxIdleConnsPerHost=100)")
	})

	if k8sConfigErr != nil {
		return nil, "", k8sConfigErr
	}

	return k8sHTTPClient, k8sBearerToken, nil
}

// getK8sTLSConfig returns a TLS config suitable for raw dialing to the k8s API.
// It triggers the sync.Once initialization via getK8sClient, then assembles a
// tls.Config from the cached globals — no duplication of kubeconfig parsing.
func (a *API) getK8sTLSConfig() (*tls.Config, error) {
	// Ensure the singleton init has run so cached TLS vars are populated.
	if _, _, err := a.getK8sClient(); err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: false,
	}
	if k8sCACertPool != nil {
		tlsCfg.RootCAs = k8sCACertPool
	}
	if k8sHasClientCert {
		tlsCfg.Certificates = []tls.Certificate{k8sClientCert}
	}
	return tlsCfg, nil
}

// isUpgradeRequest returns true if the request is a protocol upgrade (SPDY, WebSocket, etc.).
func isUpgradeRequest(r *http.Request) bool {
	// Connection header must contain "upgrade" (case-insensitive) and Upgrade header must be set.
	conn := r.Header.Get("Connection")
	if !strings.Contains(strings.ToLower(conn), "upgrade") {
		return false
	}
	return r.Header.Get("Upgrade") != ""
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

// handleK8sUpgradeProxy handles SPDY/WebSocket upgrade requests by raw TCP tunneling.
// Standard httputil.ReverseProxy strips hop-by-hop headers (Connection, Upgrade),
// which breaks kubectl exec/port-forward. Instead we hijack both ends and relay bytes.
func (a *API) handleK8sUpgradeProxy(w http.ResponseWriter, r *http.Request, k8sURL string) {
	upgradeProto := r.Header.Get("Upgrade")
	log.Printf("K8s upgrade proxy: %s %s (protocol: %s)", r.Method, k8sURL, upgradeProto)

	tlsCfg, err := a.getK8sTLSConfig()
	if err != nil {
		http.Error(w, "failed to get k8s TLS config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	backendURL, err := url.Parse(k8sServerURL)
	if err != nil || backendURL.Scheme != "https" || backendURL.Host == "" {
		http.Error(w, "Kubernetes server URL must use HTTPS for upgrades", http.StatusInternalServerError)
		return
	}
	backendPort := backendURL.Port()
	if backendPort == "" {
		backendPort = "443"
	}
	backendAddress := net.JoinHostPort(backendURL.Hostname(), backendPort)

	// Dial the configured Kubernetes API server over TLS (HTTP/1.1 — upgrades require it).
	backendConn, err := tls.Dial("tcp", backendAddress, tlsCfg)
	if err != nil {
		http.Error(w, "failed to connect to k8s API: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// Build the raw HTTP request to send over the TLS connection.
	// We need the path + query from k8sURL.
	requestURL, err := url.Parse(k8sURL)
	if err != nil {
		http.Error(w, "failed to parse Kubernetes request URL: "+err.Error(), http.StatusInternalServerError)
		return
	}
	reqURL := requestURL.RequestURI()
	var reqBuf strings.Builder
	reqBuf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, reqURL))
	reqBuf.WriteString("Host: " + backendURL.Host + "\r\n")

	// Copy all original headers, replacing Authorization with k8s credentials.
	for key, values := range r.Header {
		if strings.EqualFold(key, "Authorization") {
			continue // replaced below with k8s auth
		}
		for _, v := range values {
			reqBuf.WriteString(fmt.Sprintf("%s: %s\r\n", key, v))
		}
	}

	// Add k8s authentication.
	if k8sBearerToken != "" {
		reqBuf.WriteString("Authorization: Bearer " + k8sBearerToken + "\r\n")
	}

	reqBuf.WriteString("\r\n") // end of headers

	if _, err := backendConn.Write([]byte(reqBuf.String())); err != nil {
		http.Error(w, "failed to write to k8s API: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Hijack the client connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Read the response from k8s until end-of-headers and forward to client.
	// We read byte-by-byte to find the \r\n\r\n boundary without over-reading.
	var responseBuf []byte
	var headersDone bool
	oneByte := make([]byte, 1)
	for !headersDone {
		n, err := backendConn.Read(oneByte)
		if err != nil {
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		if n > 0 {
			responseBuf = append(responseBuf, oneByte[0])
			if len(responseBuf) >= 4 &&
				responseBuf[len(responseBuf)-4] == '\r' &&
				responseBuf[len(responseBuf)-3] == '\n' &&
				responseBuf[len(responseBuf)-2] == '\r' &&
				responseBuf[len(responseBuf)-1] == '\n' {
				headersDone = true
			}
		}
	}

	// Forward the raw response headers (including 101 Switching Protocols) to the client.
	if _, err := clientConn.Write(responseBuf); err != nil {
		return
	}

	// Flush any buffered data from the client that arrived after the HTTP headers
	// but before hijack (critical for SPDY which may send frames immediately).
	if clientBuf.Reader.Buffered() > 0 {
		buffered := make([]byte, clientBuf.Reader.Buffered())
		n, _ := clientBuf.Read(buffered)
		if n > 0 {
			backendConn.Write(buffered[:n])
		}
	}

	// Bidirectional copy — no deadlines, tunnel stays open until either side closes.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(backendConn, clientConn)
		// Half-close: signal backend that client is done writing.
		backendConn.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, backendConn)
		// Half-close: signal client that backend is done writing.
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()

	log.Printf("K8s upgrade proxy ended: %s %s", r.Method, reqURL)
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
