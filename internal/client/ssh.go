package client

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/term"

	"github.com/zyrak/zcloud/internal/shared/protocol"
)

// SSHClient cliente SSH para conexión interactiva
type SSHClient struct {
	client *Client
	config *Config
}

// NewSSHClient crea un nuevo cliente SSH
func NewSSHClient(cfg *Config) *SSHClient {
	return &SSHClient{
		client: NewClient(cfg),
		config: cfg,
	}
}

// Connect establece una sesión SSH interactiva
func (s *SSHClient) Connect() error {
	// Construir URL WebSocket
	wsURL, err := s.getWSURL()
	if err != nil {
		return fmt.Errorf("failed to build WebSocket URL: %w", err)
	}

	// Headers de autenticación
	headers := http.Header{}
	if s.config.HasValidSession() {
		headers.Set("Authorization", "Bearer "+s.config.Session.Token)
	}
	if s.config.Device.ID != "" {
		headers.Set("X-Device-ID", s.config.Device.ID)
	}

	// Dialer con TLS config
	dialer := websocket.Dialer{
		TLSClientConfig: s.client.httpClient.Transport.(*http.Transport).TLSClientConfig,
	}

	// Conectar
	conn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("authentication failed: please login first")
		}
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	fmt.Println("🔌 Connected to zcloud SSH shell")
	fmt.Println("   Type 'exit' or Ctrl+D to disconnect")
	fmt.Println()

	// Poner terminal en modo raw
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to set terminal to raw mode: %w", err)
	}
	defer func() {
		term.Restore(int(os.Stdin.Fd()), oldState)
		fmt.Println()
		fmt.Println("👋 SSH session ended")
	}()

	// Enviar tamaño inicial del terminal
	lastWidth, lastHeight := s.getTermSize()

	// Canales de control
	done := make(chan struct{})
	var closeOnce sync.Once
	closeDone := func() { closeOnce.Do(func() { close(done) }) }
	defer closeDone()
	errChan := make(chan error, 3)

	// Serialize all websocket writes through a single goroutine.
	// Gorilla websocket requires one concurrent writer.
	writeCh := make(chan protocol.SSHMessage, 64)
	go func() {
		for {
			select {
			case <-done:
				return
			case msg := <-writeCh:
				if err := conn.WriteJSON(msg); err != nil {
					errChan <- fmt.Errorf("websocket write error: %w", err)
					closeDone()
					return
				}
			}
		}
	}()

	// Enviar tamaño inicial del terminal (via writer)
	writeCh <- protocol.SSHMessage{
		Type: protocol.SSHMessageResize,
		Rows: uint16(lastHeight),
		Cols: uint16(lastWidth),
	}

	// Goroutine: stdin -> WebSocket
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				if err != io.EOF {
					errChan <- fmt.Errorf("stdin read error: %w", err)
				}
				closeDone()
				return
			}
			if n > 0 {
				msg := protocol.SSHMessage{
					Type: protocol.SSHMessageInput,
					Data: buf[:n],
				}
				select {
				case <-done:
					return
				case writeCh <- msg:
				}
			}
		}
	}()

	// Goroutine: WebSocket -> stdout
	go func() {
		for {
			var msg protocol.SSHMessage
			if err := conn.ReadJSON(&msg); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					errChan <- fmt.Errorf("websocket read error: %w", err)
				}
				closeDone()
				return
			}

			switch msg.Type {
			case protocol.SSHMessageOutput:
				os.Stdout.Write(msg.Data)
			case protocol.SSHMessageError:
				fmt.Fprintf(os.Stderr, "\r\nError: %s\r\n", string(msg.Data))
				closeDone()
				return
			case protocol.SSHMessageClose:
				closeDone()
				return
			}
		}
	}()

	// Loop principal: polling para detectar resize (funciona en todas las plataformas)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return nil
		case <-ticker.C:
			// Detectar cambio de tamaño del terminal
			width, height := s.getTermSize()
			if width != lastWidth || height != lastHeight {
				lastWidth, lastHeight = width, height
				select {
				case <-done:
					return nil
				case writeCh <- protocol.SSHMessage{
					Type: protocol.SSHMessageResize,
					Rows: uint16(height),
					Cols: uint16(width),
				}:
				}
			}
		case err := <-errChan:
			return err
		}
	}
}

// getTermSize obtiene el tamaño actual del terminal
func (s *SSHClient) getTermSize() (int, int) {
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		return 80, 24
	}
	return width, height
}

// sendTermSize envía el tamaño actual del terminal
// sendTermSize removed: writes are serialized via writeCh in Connect().

// getWSURL genera la URL WebSocket a partir de la URL HTTP
func (s *SSHClient) getWSURL() (string, error) {
	serverURL := s.config.Server.URL

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

	// Path del endpoint SSH
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/v1/ssh/shell"

	return u.String(), nil
}

// SSHFromAuth crea un cliente SSH desde un Auth existente
func SSHFromAuth(auth *Auth) *SSHClient {
	return NewSSHClient(auth.config)
}
