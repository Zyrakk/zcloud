package api

import (
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"

	"github.com/zyrak/zcloud/internal/server/middleware"
	"github.com/zyrak/zcloud/internal/shared/protocol"
)

func newUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == ""
		},
	}
}

// handleSSHShell maneja conexiones SSH interactivas vía WebSocket
func (a *API) handleSSHShell(w http.ResponseWriter, r *http.Request) {
	deviceID := middleware.GetDeviceID(r)
	log.Printf("SSH session started for device: %s", deviceID)

	// Upgrade a WebSocket
	upgrader := newUpgrader()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	conn.SetReadLimit(64 * 1024) // 64KB

	// Crear comando shell
	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell)
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		homeDir = os.TempDir()
	}
	cmd.Env = []string{
		"TERM=xterm-256color",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + homeDir,
		"SHELL=" + shell,
		"LANG=" + os.Getenv("LANG"),
		"PS1=\\u@zcloud:\\w\\$ ",
	}

	// Iniciar PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("Failed to start PTY: %v", err)
		sendSSHError(conn, "failed to start shell")
		return
	}
	defer func() {
		_ = ptmx.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Controlar fin de goroutines
	var wg sync.WaitGroup
	done := make(chan struct{})

	// Goroutine: PTY -> WebSocket (output del shell)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
				n, err := ptmx.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Printf("PTY read error: %v", err)
					}
					return
				}
				if n > 0 {
					msg := protocol.SSHMessage{
						Type: protocol.SSHMessageOutput,
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

	// Goroutine: WebSocket -> PTY (input del usuario)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)

		for {
			var msg protocol.SSHMessage
			if err := conn.ReadJSON(&msg); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					log.Printf("WebSocket read error: %v", err)
				}
				return
			}

			switch msg.Type {
			case protocol.SSHMessageInput:
				if _, err := ptmx.Write(msg.Data); err != nil {
					log.Printf("PTY write error: %v", err)
					return
				}

			case protocol.SSHMessageResize:
				setWinsize(ptmx, msg.Rows, msg.Cols)

			case protocol.SSHMessageClose:
				return
			}
		}
	}()

	// Esperar fin
	wg.Wait()
	log.Printf("SSH session ended for device: %s", deviceID)
}

// setWinsize cambia el tamaño del terminal
func setWinsize(f *os.File, rows, cols uint16) {
	ws := struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	}{
		Row: rows,
		Col: cols,
	}
	syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TIOCSWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
}

// sendSSHError envía un mensaje de error al cliente
func sendSSHError(conn *websocket.Conn, message string) {
	msg := protocol.SSHMessage{
		Type: protocol.SSHMessageError,
		Data: []byte(message),
	}
	_ = conn.WriteJSON(msg)
}
