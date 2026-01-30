package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zyrak/zcloud/internal/server/db"
	"github.com/zyrak/zcloud/internal/server/middleware"
	"github.com/zyrak/zcloud/internal/shared/crypto"
	"github.com/zyrak/zcloud/internal/shared/protocol"
)

// API representa el servidor API
type API struct {
	db     *db.Database
	auth   *middleware.AuthMiddleware
	config *Config
}

// Config configuración de la API
type Config struct {
	JWTSecret       string
	SessionTTL      time.Duration
	TOTPIssuer      string
	RequireApproval bool
	KubeconfigPath  string
	CoreDNSIP       string
}

// New crea una nueva API
func New(database *db.Database, config *Config) *API {
	auth := middleware.NewAuthMiddleware(config.JWTSecret)
	auth.SetDatabase(database)
	return &API{
		db:     database,
		auth:   auth,
		config: config,
	}
}

// Router configura las rutas
func (a *API) Router() http.Handler {
	mux := http.NewServeMux()

	// Rutas públicas (sin autenticación)
	mux.HandleFunc("POST /api/v1/devices/register", a.handleRegister)
	mux.HandleFunc("GET /api/v1/devices/status", a.handleDeviceStatus)
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)

	// Rutas protegidas
	protected := http.NewServeMux()
	protected.HandleFunc("POST /api/v1/auth/logout", a.handleLogout)
	protected.HandleFunc("GET /api/v1/status/cluster", a.handleClusterStatus)
	protected.HandleFunc("POST /api/v1/k8s/apply", a.handleApply)
	protected.HandleFunc("/api/v1/k8s/proxy/", a.handleK8sProxy)
	protected.HandleFunc("POST /api/v1/ssh/exec", a.handleExec)

	// SSH Shell (WebSocket)
	protected.HandleFunc("GET /api/v1/ssh/shell", a.handleSSHShell)

	// File transfer
	protected.HandleFunc("POST /api/v1/files/upload", a.handleFileUpload)
	protected.HandleFunc("GET /api/v1/files/download", a.handleFileDownload)
	protected.HandleFunc("GET /api/v1/files/list", a.handleFileList)
	protected.HandleFunc("DELETE /api/v1/files/delete", a.handleFileDelete)

	// Port forwarding (WebSocket)
	protected.HandleFunc("GET /api/v1/portforward", a.handlePortForward)

	// Rutas de admin
	admin := http.NewServeMux()
	admin.HandleFunc("GET /api/v1/admin/devices", a.handleListDevices)
	admin.HandleFunc("POST /api/v1/admin/devices/{id}/approve", a.handleApproveDevice)
	admin.HandleFunc("POST /api/v1/admin/devices/{id}/revoke", a.handleRevokeDevice)
	admin.HandleFunc("GET /api/v1/admin/sessions", a.handleListSessions)

	// Aplicar middleware
	mux.Handle("/api/v1/auth/", a.auth.Authenticate(protected))
	mux.Handle("/api/v1/status/", a.auth.Authenticate(protected))
	mux.Handle("/api/v1/k8s/", a.auth.Authenticate(protected))
	mux.Handle("/api/v1/ssh/", a.auth.Authenticate(protected))
	mux.Handle("/api/v1/files/", a.auth.Authenticate(protected))
	mux.Handle("/api/v1/portforward", a.auth.Authenticate(protected))
	mux.Handle("/api/v1/admin/", a.auth.Authenticate(a.auth.RequireAdmin(admin)))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "ok"}`))
	})

	// Aplicar middleware global
	rateLimiter := middleware.NewRateLimiter(100, time.Minute)
	handler := middleware.Logger(middleware.CORS(rateLimiter.Limit(mux)))

	return handler
}

// Handlers

func (a *API) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req protocol.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validar campos requeridos
	if req.DeviceName == "" || req.PublicKey == "" {
		a.jsonError(w, "device_name and public_key are required", http.StatusBadRequest)
		return
	}

	// Verificar si ya existe
	existing, err := a.db.GetDeviceByPublicKey(req.PublicKey)
	if err != nil {
		a.jsonError(w, "database error", http.StatusInternalServerError)
		return
	}
	if existing != nil {
		// Ya existe, devolver su estado
		resp := &protocol.RegisterResponse{
			DeviceID: existing.ID,
			Status:   existing.Status,
			Message:  "device already registered",
		}
		a.jsonResponse(w, resp, http.StatusOK)
		return
	}

	// Generar ID único
	deviceID := generateDeviceID(req.PublicKey)

	// Estado inicial
	status := protocol.DeviceStatusApproved
	if a.config.RequireApproval {
		status = protocol.DeviceStatusPending
	}

	// Generar TOTP si está aprobado automáticamente
	var totpSecret, totpQR string
	if status == protocol.DeviceStatusApproved {
		totpSecret, totpQR, err = crypto.GenerateTOTP(crypto.TOTPConfig{
			Issuer:      a.config.TOTPIssuer,
			AccountName: req.DeviceName,
		})
		if err != nil {
			a.jsonError(w, "failed to generate TOTP", http.StatusInternalServerError)
			return
		}
	}

	// Crear dispositivo
	device := &protocol.DeviceInfo{
		ID:        deviceID,
		Name:      req.DeviceName,
		PublicKey: req.PublicKey,
		Hostname:  req.Hostname,
		OS:        req.OS,
		Status:    status,
		CreatedAt: time.Now(),
	}

	if err := a.db.CreateDevice(device, totpSecret); err != nil {
		a.jsonError(w, "failed to create device", http.StatusInternalServerError)
		return
	}

	// Respuesta
	resp := &protocol.RegisterResponse{
		DeviceID:   deviceID,
		Status:     status,
		TOTPSecret: totpSecret,
		TOTPQR:     totpQR,
	}

	if status == protocol.DeviceStatusPending {
		resp.Message = "Device registered, awaiting approval"
		// TODO: Enviar notificación al admin (Telegram, etc.)
		log.Printf("New device pending approval: %s (%s)", req.DeviceName, deviceID)
	}

	a.jsonResponse(w, resp, http.StatusCreated)
}

func (a *API) handleDeviceStatus(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		a.jsonError(w, "device_id is required", http.StatusBadRequest)
		return
	}

	device, err := a.db.GetDevice(deviceID)
	if err != nil {
		a.jsonError(w, "database error", http.StatusInternalServerError)
		return
	}
	if device == nil {
		a.jsonError(w, "device not found", http.StatusNotFound)
		return
	}

	resp := &protocol.RegisterResponse{
		DeviceID: device.ID,
		Status:   device.Status,
	}

	// Si está aprobado, incluir TOTP si no lo tiene configurado
	if device.Status == protocol.DeviceStatusApproved {
		totpSecret, err := a.db.GetTOTPSecret(deviceID)
		if err == nil && totpSecret != "" {
			resp.TOTPSecret = totpSecret
			// Generar QR del secreto existente (no regenerar secreto)
			resp.TOTPQR, _ = crypto.GenerateTOTPQRFromSecret(totpSecret, crypto.TOTPConfig{
				Issuer:      a.config.TOTPIssuer,
				AccountName: device.Name,
			})
		}
	}

	a.jsonResponse(w, resp, http.StatusOK)
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req protocol.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Obtener dispositivo
	device, err := a.db.GetDevice(req.DeviceID)
	if err != nil || device == nil {
		a.jsonError(w, "device not found", http.StatusUnauthorized)
		return
	}

	// Verificar que está aprobado
	if device.Status != protocol.DeviceStatusApproved {
		a.jsonError(w, "device not approved", http.StatusForbidden)
		return
	}

	// Verificar timestamp (prevenir replay attacks, ventana de 5 minutos)
	now := time.Now().Unix()
	if req.Timestamp < now-300 || req.Timestamp > now+60 {
		a.jsonError(w, "invalid timestamp", http.StatusUnauthorized)
		return
	}

	// Verificar firma
	message := strconv.FormatInt(req.Timestamp, 10)
	valid, err := crypto.VerifySignature(device.PublicKey, message, req.Signature)
	if err != nil || !valid {
		a.jsonError(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// Verificar TOTP
	totpSecret, err := a.db.GetTOTPSecret(req.DeviceID)
	if err != nil || totpSecret == "" {
		a.jsonError(w, "TOTP not configured", http.StatusInternalServerError)
		return
	}

	if !crypto.ValidateTOTP(totpSecret, req.TOTPCode) {
		a.jsonError(w, "invalid TOTP code", http.StatusUnauthorized)
		return
	}

	// Verificar si es admin
	isAdmin, _ := a.db.IsAdmin(req.DeviceID)

	// Generar token
	token, expiresAt, err := a.auth.GenerateToken(req.DeviceID, device.Name, isAdmin, a.config.SessionTTL)
	if err != nil {
		a.jsonError(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	// Guardar sesión
	sessionID := uuid.New().String()
	tokenHash := hashToken(token)
	ip := r.RemoteAddr
	if err := a.db.CreateSession(sessionID, req.DeviceID, tokenHash, expiresAt, ip); err != nil {
		log.Printf("Failed to save session: %v", err)
	}

	// Actualizar último acceso
	_ = a.db.UpdateDeviceLastAccess(req.DeviceID)

	resp := &protocol.LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		Message:   "Login successful",
	}

	a.jsonResponse(w, resp, http.StatusOK)
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	deviceID := middleware.GetDeviceID(r)

	// Obtener el token del header Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Revocar el token
		tokenHash := hashToken(tokenString)
		expiresAt := time.Now().Add(a.config.SessionTTL)
		_ = a.db.RevokeToken(tokenHash, expiresAt, "user_logout")
	}

	// Eliminar sesiones del dispositivo
	_ = a.db.DeleteDeviceSessions(deviceID)

	a.jsonResponse(w, map[string]string{"message": "Logged out"}, http.StatusOK)
}

func (a *API) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	deviceID := middleware.GetDeviceID(r)

	// Ejecutar kubectl get nodes
	cmd := exec.Command("kubectl", "--kubeconfig", a.config.KubeconfigPath, "get", "nodes", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		a.jsonError(w, "failed to get cluster status", http.StatusInternalServerError)
		return
	}

	// Parsear output
	var nodesResp struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}

	if err := json.Unmarshal(output, &nodesResp); err != nil {
		a.jsonError(w, "failed to parse cluster status", http.StatusInternalServerError)
		return
	}

	// Construir respuesta
	var nodes []protocol.NodeInfo
	for _, item := range nodesResp.Items {
		status := "Unknown"
		for _, cond := range item.Status.Conditions {
			if cond.Type == "Ready" {
				if cond.Status == "True" {
					status = "Ready"
				} else {
					status = "NotReady"
				}
				break
			}
		}

		role := item.Metadata.Labels["role"]
		if role == "" {
			role = "worker"
		}

		nodes = append(nodes, protocol.NodeInfo{
			Name:   item.Metadata.Name,
			Role:   role,
			Status: status,
		})
	}

	device, _ := a.db.GetDevice(deviceID)

	resp := &protocol.StatusResponse{
		Connected:   true,
		ClusterName: "zcloud-k3s",
		Nodes:       nodes,
		Session: protocol.SessionInfo{
			DeviceID:   deviceID,
			DeviceName: device.Name,
			Valid:      true,
		},
	}

	a.jsonResponse(w, resp, http.StatusOK)
}

func (a *API) handleApply(w http.ResponseWriter, r *http.Request) {
	var req protocol.ApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var results []protocol.ApplyResult

	for _, manifest := range req.Manifests {
		// Crear archivo temporal
		tmpFile := fmt.Sprintf("/tmp/zcloud-manifest-%s.yaml", uuid.New().String()[:8])
		if err := exec.Command("sh", "-c", fmt.Sprintf("cat > %s << 'EOF'\n%s\nEOF", tmpFile, manifest)).Run(); err != nil {
			results = append(results, protocol.ApplyResult{
				Error: fmt.Sprintf("failed to write manifest: %v", err),
			})
			continue
		}

		// Aplicar manifest
		args := []string{"--kubeconfig", a.config.KubeconfigPath, "apply", "-f", tmpFile}
		if req.Namespace != "" {
			args = append(args, "-n", req.Namespace)
		}
		if req.DryRun {
			args = append(args, "--dry-run=client")
		}

		cmd := exec.Command("kubectl", args...)
		output, err := cmd.CombinedOutput()

		// Limpiar archivo temporal
		exec.Command("rm", "-f", tmpFile).Run()

		if err != nil {
			results = append(results, protocol.ApplyResult{
				Error: string(output),
			})
		} else {
			// Parsear output para obtener detalles
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if line == "" {
					continue
				}
				// Formato: "resource/name action"
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					kindName := strings.Split(parts[0], "/")
					kind := ""
					name := parts[0]
					if len(kindName) == 2 {
						kind = kindName[0]
						name = kindName[1]
					}
					results = append(results, protocol.ApplyResult{
						Kind:   kind,
						Name:   name,
						Action: parts[len(parts)-1],
					})
				}
			}
		}
	}

	// Verificar si hubo errores
	success := true
	for _, r := range results {
		if r.Error != "" {
			success = false
			break
		}
	}

	resp := &protocol.ApplyResponse{
		Results: results,
		Success: success,
	}

	a.jsonResponse(w, resp, http.StatusOK)
}

func (a *API) handleExec(w http.ResponseWriter, r *http.Request) {
	var req protocol.ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validar comando (whitelist básica)
	allowedCommands := map[string]bool{
		"kubectl": true,
		"helm":    true,
		"k3s":     true,
	}

	if !allowedCommands[req.Command] {
		a.jsonError(w, "command not allowed", http.StatusForbidden)
		return
	}

	// Ejecutar comando
	cmd := exec.Command(req.Command, req.Args...)
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}

	stdout, err := cmd.Output()
	stderr := ""
	exitCode := 0

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
			exitCode = exitErr.ExitCode()
		} else {
			stderr = err.Error()
			exitCode = 1
		}
	}

	resp := &protocol.ExecResponse{
		Stdout:   string(stdout),
		Stderr:   stderr,
		ExitCode: exitCode,
	}

	a.jsonResponse(w, resp, http.StatusOK)
}

// Admin handlers

func (a *API) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := a.db.ListDevices()
	if err != nil {
		a.jsonError(w, "failed to list devices", http.StatusInternalServerError)
		return
	}

	a.jsonResponse(w, devices, http.StatusOK)
}

func (a *API) handleApproveDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	if deviceID == "" {
		a.jsonError(w, "device id is required", http.StatusBadRequest)
		return
	}

	device, err := a.db.GetDevice(deviceID)
	if err != nil || device == nil {
		a.jsonError(w, "device not found", http.StatusNotFound)
		return
	}

	if device.Status == protocol.DeviceStatusApproved {
		a.jsonError(w, "device already approved", http.StatusBadRequest)
		return
	}

	// Generar TOTP
	totpSecret, _, err := crypto.GenerateTOTP(crypto.TOTPConfig{
		Issuer:      a.config.TOTPIssuer,
		AccountName: device.Name,
	})
	if err != nil {
		a.jsonError(w, "failed to generate TOTP", http.StatusInternalServerError)
		return
	}

	// Actualizar dispositivo
	if err := a.db.UpdateDeviceStatus(deviceID, protocol.DeviceStatusApproved); err != nil {
		a.jsonError(w, "failed to update device", http.StatusInternalServerError)
		return
	}

	if err := a.db.UpdateDeviceTOTP(deviceID, totpSecret); err != nil {
		a.jsonError(w, "failed to update TOTP", http.StatusInternalServerError)
		return
	}

	log.Printf("Device approved: %s (%s)", device.Name, deviceID)

	a.jsonResponse(w, map[string]string{"message": "Device approved"}, http.StatusOK)
}

func (a *API) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	if deviceID == "" {
		a.jsonError(w, "device id is required", http.StatusBadRequest)
		return
	}

	device, err := a.db.GetDevice(deviceID)
	if err != nil || device == nil {
		a.jsonError(w, "device not found", http.StatusNotFound)
		return
	}

	// Actualizar estado
	if err := a.db.UpdateDeviceStatus(deviceID, protocol.DeviceStatusRevoked); err != nil {
		a.jsonError(w, "failed to update device", http.StatusInternalServerError)
		return
	}

	// Revocar todos los tokens del dispositivo
	_ = a.db.RevokeDeviceTokens(deviceID)

	log.Printf("Device revoked: %s (%s)", device.Name, deviceID)

	a.jsonResponse(w, map[string]string{"message": "Device revoked"}, http.StatusOK)
}

func (a *API) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := a.db.GetActiveSessions()
	if err != nil {
		a.jsonError(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}

	a.jsonResponse(w, sessions, http.StatusOK)
}

// Helpers

func (a *API) jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (a *API) jsonError(w http.ResponseWriter, message string, status int) {
	a.jsonResponse(w, protocol.ErrorResponse{Error: message}, status)
}

func generateDeviceID(publicKey string) string {
	hash := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(hash[:])[:12]
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
