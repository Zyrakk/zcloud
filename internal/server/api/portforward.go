package api

import (
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/zyrak/zcloud/internal/server/middleware"
	"github.com/zyrak/zcloud/internal/shared/protocol"
)

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

	// Conectar al destino
	targetAddr := net.JoinHostPort(targetHost, targetPortStr)
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
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
