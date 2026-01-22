package client

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/zyrak/zcloud/internal/shared/protocol"
)

// PortForwardClient cliente para port forwarding
type PortForwardClient struct {
	client *Client
	config *Config
}

// NewPortForwardClient crea un nuevo cliente de port forwarding
func NewPortForwardClient(cfg *Config) *PortForwardClient {
	return &PortForwardClient{
		client: NewClient(cfg),
		config: cfg,
	}
}

// Forward inicia el port forwarding
// localPort: puerto local donde escuchar
// targetHost: host destino en el servidor (ej: "grafana.monitoring.svc", "localhost")
// targetPort: puerto destino
func (p *PortForwardClient) Forward(localPort int, targetHost string, targetPort int) error {
	// Crear listener local
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", localPort, err)
	}
	defer listener.Close()

	fmt.Printf("🔌 Forwarding localhost:%d -> %s:%d\n", localPort, targetHost, targetPort)
	fmt.Println("   Press Ctrl+C to stop")

	// Aceptar conexiones
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		// Manejar cada conexión en una goroutine
		go p.handleConnection(conn, targetHost, targetPort)
	}
}

// handleConnection maneja una conexión TCP entrante
func (p *PortForwardClient) handleConnection(conn net.Conn, targetHost string, targetPort int) {
	defer conn.Close()

	// Conectar al servidor via WebSocket
	wsURL, err := p.getWSURL(targetHost, targetPort)
	if err != nil {
		log.Printf("Failed to build WebSocket URL: %v", err)
		return
	}

	// Headers de autenticación
	headers := http.Header{}
	if p.config.HasValidSession() {
		headers.Set("Authorization", "Bearer "+p.config.Session.Token)
	}
	if p.config.Device.ID != "" {
		headers.Set("X-Device-ID", p.config.Device.ID)
	}

	// Dialer con TLS config
	dialer := websocket.Dialer{
		TLSClientConfig: p.client.httpClient.Transport.(*http.Transport).TLSClientConfig,
	}

	// Conectar
	wsConn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			log.Printf("Authentication failed: please login first")
			return
		}
		log.Printf("WebSocket connection failed: %v", err)
		return
	}
	defer wsConn.Close()

	// Bidirectional relay
	var wg sync.WaitGroup
	done := make(chan struct{})

	// Goroutine: TCP -> WebSocket
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)

		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("TCP read error: %v", err)
				}
				// Enviar cierre
				msg := protocol.PortForwardMessage{
					Type: protocol.PortForwardClose,
				}
				_ = wsConn.WriteJSON(msg)
				return
			}
			if n > 0 {
				msg := protocol.PortForwardMessage{
					Type: protocol.PortForwardData,
					Data: buf[:n],
				}
				if err := wsConn.WriteJSON(msg); err != nil {
					log.Printf("WebSocket write error: %v", err)
					return
				}
			}
		}
	}()

	// Goroutine: WebSocket -> TCP
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-done:
				return
			default:
				var msg protocol.PortForwardMessage
				if err := wsConn.ReadJSON(&msg); err != nil {
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
						log.Printf("WebSocket read error: %v", err)
					}
					return
				}

				switch msg.Type {
				case protocol.PortForwardData:
					if _, err := conn.Write(msg.Data); err != nil {
						log.Printf("TCP write error: %v", err)
						return
					}
				case protocol.PortForwardError:
					log.Printf("Remote error: %s", string(msg.Data))
					return
				case protocol.PortForwardClose:
					return
				}
			}
		}
	}()

	wg.Wait()
}

// getWSURL genera la URL WebSocket para port forwarding
func (p *PortForwardClient) getWSURL(targetHost string, targetPort int) (string, error) {
	serverURL := p.config.Server.URL

	// Parsear URL
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", err
	}

	// Cambiar esquema a WebSocket
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		u.Scheme = "wss"
	}

	// Path del endpoint
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/v1/portforward"

	// Query params
	q := u.Query()
	q.Set("host", targetHost)
	q.Set("port", strconv.Itoa(targetPort))
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// PortForwardFromAuth crea un cliente de port forwarding desde Auth
func PortForwardFromAuth(auth *Auth) *PortForwardClient {
	return NewPortForwardClient(auth.config)
}
