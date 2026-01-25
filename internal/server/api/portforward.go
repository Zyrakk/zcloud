package api

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/zyrak/zcloud/internal/server/middleware"
	"github.com/zyrak/zcloud/internal/shared/protocol"
)

// k3s CoreDNS default IP (kube-dns service in kube-system)
const k3sCoreDNSIP = "10.43.0.10:53"

// k8sSuffixes are domain suffixes that should use k8s DNS
var k8sSuffixes = []string{
	".svc.cluster.local",
	".svc",
	".pod.cluster.local",
	".pod",
}

// isK8sHostname checks if hostname should use k8s DNS
func isK8sHostname(host string) bool {
	hostLower := strings.ToLower(host)
	for _, suffix := range k8sSuffixes {
		if strings.HasSuffix(hostLower, suffix) {
			return true
		}
	}
	return false
}

// resolveK8sHostname resolves a k8s service name using CoreDNS
func resolveK8sHostname(ctx context.Context, host string) (string, error) {
	// Normalize: add .cluster.local if needed
	normalizedHost := host
	if strings.HasSuffix(host, ".svc") && !strings.HasSuffix(host, ".svc.cluster.local") {
		normalizedHost = host + ".cluster.local"
	} else if strings.HasSuffix(host, ".pod") && !strings.HasSuffix(host, ".pod.cluster.local") {
		normalizedHost = host + ".cluster.local"
	}

	// Create resolver pointing to k3s CoreDNS
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", k3sCoreDNSIP)
		},
	}

	// Resolve
	ips, err := resolver.LookupHost(ctx, normalizedHost)
	if err != nil {
		return "", err
	}

	if len(ips) == 0 {
		return "", &net.DNSError{Err: "no addresses found", Name: normalizedHost}
	}

	log.Printf("Resolved k8s hostname %s -> %s", host, ips[0])
	return ips[0], nil
}

// dialTarget connects to target, using k8s DNS for service names
func dialTarget(ctx context.Context, host string, port string) (net.Conn, error) {
	resolvedHost := host

	// Use k8s DNS for kubernetes hostnames
	if isK8sHostname(host) {
		ip, err := resolveK8sHostname(ctx, host)
		if err != nil {
			return nil, err
		}
		resolvedHost = ip
	}

	// Connect
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(resolvedHost, port))
}

// handlePortForward maneja conexiones de port forwarding vía WebSocket
func (a *API) handlePortForward(w http.ResponseWriter, r *http.Request) {
	deviceID := middleware.GetDeviceID(r)

	// Obtener parámetros
	targetHost := r.URL.Query().Get("host")
	targetPortStr := r.URL.Query().Get("port")

	if targetHost == "" || targetPortStr == "" {
		http.Error(w, "host and port are required", http.StatusBadRequest)
		return
	}

	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil || targetPort <= 0 || targetPort > 65535 {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}

	log.Printf("Port forward started for device %s: -> %s:%d", deviceID, targetHost, targetPort)

	// Upgrade a WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// Conectar al destino usando k8s DNS si es necesario
	ctx := r.Context()
	targetConn, err := dialTarget(ctx, targetHost, targetPortStr)
	if err != nil {
		log.Printf("Failed to connect to target %s:%s: %v", targetHost, targetPortStr, err)
		sendPortForwardError(conn, "failed to connect to target: "+err.Error())
		return
	}
	defer targetConn.Close()

	// Bidirectional relay
	var wg sync.WaitGroup
	done := make(chan struct{})

	// Goroutine: Target TCP -> WebSocket
	wg.Add(1)
	go func() {
		defer wg.Done()

		buf := make([]byte, 32*1024)
		for {
			select {
			case <-done:
				return
			default:
				n, err := targetConn.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Printf("Target read error: %v", err)
					}
					return
				}
				if n > 0 {
					msg := protocol.PortForwardMessage{
						Type: protocol.PortForwardData,
						Data: buf[:n],
					}
					if err := conn.WriteJSON(msg); err != nil {
						log.Printf("WebSocket write error: %v", err)
						return
					}
				}
			}
		}
	}()

	// Goroutine: WebSocket -> Target TCP
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)

		for {
			var msg protocol.PortForwardMessage
			if err := conn.ReadJSON(&msg); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					log.Printf("WebSocket read error: %v", err)
				}
				return
			}

			switch msg.Type {
			case protocol.PortForwardData:
				if _, err := targetConn.Write(msg.Data); err != nil {
					log.Printf("Target write error: %v", err)
					return
				}
			case protocol.PortForwardClose:
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("Port forward ended for device %s: -> %s:%d", deviceID, targetHost, targetPort)
}

// sendPortForwardError envía un mensaje de error al cliente
func sendPortForwardError(conn *websocket.Conn, message string) {
	msg := protocol.PortForwardMessage{
		Type: protocol.PortForwardError,
		Data: []byte(message),
	}
	_ = conn.WriteJSON(msg)
}
