package api

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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
	db          *db.Database
	auth        *middleware.AuthMiddleware
	config      *Config
	auditLogger *middleware.AuditLogger
}

// Config configuración de la API
type Config struct {
	JWTSecret       string
	SessionTTL      time.Duration
	TOTPIssuer      string
	RequireApproval bool
	KubeconfigPath  string
	CoreDNSIP       string
	CACertPath      string
}

// New crea una nueva API
func New(database *db.Database, config *Config) *API {
	auth := middleware.NewAuthMiddleware(config.JWTSecret)
	auth.SetDatabase(database)

	// Create audit logger
	auditLogger := middleware.NewAuditLogger("info")

	return &API{
		db:          database,
		auth:        auth,
		config:      config,
		auditLogger: auditLogger,
	}
}

// Router configura las rutas
func (a *API) Router() http.Handler {
	mux := http.NewServeMux()

	// Rutas públicas (sin autenticación)
	mux.HandleFunc("POST /api/v1/devices/register", a.handleRegister)
	mux.HandleFunc("GET /api/v1/devices/status", a.handleDeviceStatus)
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)
	mux.HandleFunc("POST /api/v1/totp/enroll", a.handleTOTPEnroll)

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
	mux.HandleFunc("GET /health", a.handleHealthCheck)
	mux.HandleFunc("GET /ready", a.handleReadyCheck)

	// Aplicar middleware global
	rateLimiter := middleware.NewRateLimiter(100, time.Minute)
	handler := middleware.Logger(middleware.SecurityHeaders(middleware.CORS(rateLimiter.Limit(mux))))

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

	// En modo auto-approval, creamos un "usuario" por defecto para este dispositivo y emitimos
	// un código de enrolamiento one-time para que el usuario obtenga el secreto en su terminal.
	var (
		userID             string
		userName           string
		enrollmentCode     string
		enrollmentExpires  time.Time
		totpSecretForStore string
	)
	if status == protocol.DeviceStatusApproved {
		userID = uuid.New().String()
		// Make user name unique to avoid collisions when auto-approving.
		userName = fmt.Sprintf("%s-%s", req.DeviceName, deviceID[:6])
		totpSecretForStore, _, err = crypto.GenerateTOTP(crypto.TOTPConfig{
			Issuer:      a.config.TOTPIssuer,
			AccountName: userName,
		})
		if err != nil {
			a.jsonError(w, "failed to generate TOTP", http.StatusInternalServerError)
			return
		}
		if err := a.db.CreateUser(userID, userName, totpSecretForStore); err != nil {
			a.jsonError(w, "failed to create user", http.StatusInternalServerError)
			return
		}

		enrollmentCode = generateEnrollmentCode()
		enrollmentExpires = time.Now().Add(10 * time.Minute)
		if err := a.db.CreateTOTPEnrollment(hashEnrollmentCode(enrollmentCode), deviceID, userID, enrollmentExpires); err != nil {
			a.jsonError(w, "failed to create enrollment code", http.StatusInternalServerError)
			return
		}
	}

	// Crear dispositivo
	device := &protocol.DeviceInfo{
		ID:        deviceID,
		UserID:    userID,
		Name:      req.DeviceName,
		PublicKey: req.PublicKey,
		Hostname:  req.Hostname,
		OS:        req.OS,
		Status:    status,
		CreatedAt: time.Now(),
	}

	// totp_secret in devices is legacy; for the new model we store it in users.
	if err := a.db.CreateDevice(device, ""); err != nil {
		a.jsonError(w, "failed to create device", http.StatusInternalServerError)
		return
	}

	// Respuesta
	resp := &protocol.RegisterResponse{
		DeviceID:            deviceID,
		Status:              status,
		EnrollmentCode:      enrollmentCode,
		EnrollmentExpiresAt: enrollmentExpires,
	}

	if status == protocol.DeviceStatusPending {
		resp.Message = "Device registered, awaiting approval"
		// TODO: Enviar notificación al admin (Telegram, etc.)
		log.Printf("New device pending approval: %s (%s)", req.DeviceName, deviceID)

		// Audit log
		deviceIP := r.RemoteAddr
		a.auditLogger.LogAudit("device_pending", deviceID, fmt.Sprintf("name=%s hostname=%s os=%s ip=%s", req.DeviceName, req.Hostname, req.OS, deviceIP))
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
	var totpSecret string
	if device.UserID != "" {
		secret, _, err := a.db.GetUserTOTPSecret(device.UserID)
		if err != nil {
			a.jsonError(w, "failed to get user TOTP", http.StatusInternalServerError)
			return
		}
		totpSecret = secret
	} else {
		// Legacy fallback (older DBs / flows).
		secret, err := a.db.GetTOTPSecret(req.DeviceID)
		if err != nil {
			a.jsonError(w, "failed to get TOTP", http.StatusInternalServerError)
			return
		}
		totpSecret = secret
	}

	if totpSecret == "" {
		a.jsonError(w, "TOTP not configured", http.StatusForbidden)
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

	// Audit log
	loginIP := r.RemoteAddr
	a.auditLogger.LogAudit("login_success", req.DeviceID, fmt.Sprintf("ip=%s", loginIP))

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

		// Audit log
		logoutIP := r.RemoteAddr
		a.auditLogger.LogAudit("logout", deviceID, fmt.Sprintf("ip=%s", logoutIP))
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
		// Apply manifests via stdin to avoid shell injection / temp file issues.
		args := []string{"--kubeconfig", a.config.KubeconfigPath, "apply", "-f", "-"}
		if req.Namespace != "" {
			args = append(args, "-n", req.Namespace)
		}
		if req.DryRun {
			args = append(args, "--dry-run=client")
		}

		cmd := exec.Command("kubectl", args...)
		cmd.Stdin = bytes.NewBufferString(manifest + "\n")
		output, err := cmd.CombinedOutput()

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

	// Execute command with a controlled environment (ensure KUBECONFIG for k8s tooling).
	cmd := exec.Command(req.Command, req.Args...)
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}

	env := os.Environ()
	if a.config.KubeconfigPath != "" {
		// Force tools to use the server's kubeconfig unless they explicitly override it.
		env = append(env, "KUBECONFIG="+a.config.KubeconfigPath)
	}
	cmd.Env = env

	// Capture stdout/stderr reliably (even on success).
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
			// Preserve the error string if the process didn't run at all.
			if stderrBuf.Len() == 0 {
				stderrBuf.WriteString(err.Error())
			}
		}
	}

	resp := &protocol.ExecResponse{
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
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

	// Determine the "persona" (user) this device belongs to.
	// Accept query param ?user=... or JSON body {"user":"..."}; fallback to device name.
	userName := strings.TrimSpace(r.URL.Query().Get("user"))
	if userName == "" {
		var body struct {
			User string `json:"user"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		userName = strings.TrimSpace(body.User)
	}
	if userName == "" {
		userName = device.Name
	}

	// Ensure user exists (create with TOTP secret if missing).
	u, err := a.db.GetUserByName(userName)
	if err != nil {
		a.jsonError(w, "failed to load user", http.StatusInternalServerError)
		return
	}
	if u == nil {
		userID := uuid.New().String()
		secret, _, err := crypto.GenerateTOTP(crypto.TOTPConfig{
			Issuer:      a.config.TOTPIssuer,
			AccountName: userName,
		})
		if err != nil {
			a.jsonError(w, "failed to generate TOTP", http.StatusInternalServerError)
			return
		}
		if err := a.db.CreateUser(userID, userName, secret); err != nil {
			a.jsonError(w, "failed to create user", http.StatusInternalServerError)
			return
		}
		u, _ = a.db.GetUser(userID)
	}
	if u == nil {
		a.jsonError(w, "failed to resolve user", http.StatusInternalServerError)
		return
	}

	// Actualizar dispositivo
	if err := a.db.UpdateDeviceStatus(deviceID, protocol.DeviceStatusApproved); err != nil {
		a.jsonError(w, "failed to update device", http.StatusInternalServerError)
		return
	}

	// Assign device to user for per-person TOTP.
	if err := a.db.SetDeviceUserID(deviceID, u.ID); err != nil {
		a.jsonError(w, "failed to assign device to user", http.StatusInternalServerError)
		return
	}

	// Create a one-time enrollment code for the user to retrieve the secret on their terminal.
	enrollmentCode := generateEnrollmentCode()
	enrollmentExpires := time.Now().Add(10 * time.Minute)
	if err := a.db.CreateTOTPEnrollment(hashEnrollmentCode(enrollmentCode), deviceID, u.ID, enrollmentExpires); err != nil {
		a.jsonError(w, "failed to create enrollment code", http.StatusInternalServerError)
		return
	}

	log.Printf("Device approved: %s (%s)", device.Name, deviceID)

	// Audit log
	approveIP := r.RemoteAddr
	a.auditLogger.LogAudit("device_approved", deviceID, fmt.Sprintf("name=%s ip=%s", device.Name, approveIP))

	a.jsonResponse(w, &protocol.ApproveDeviceResponse{
		Message:             "Device approved",
		UserID:              u.ID,
		UserName:            u.Name,
		EnrollmentCode:      enrollmentCode,
		EnrollmentExpiresAt: enrollmentExpires,
	}, http.StatusOK)
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

	// Audit log
	revokeIP := r.RemoteAddr
	a.auditLogger.LogAudit("device_revoked", deviceID, fmt.Sprintf("name=%s ip=%s", device.Name, revokeIP))

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

// handleHealthCheck is a simple health check endpoint
func (a *API) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
}

// handleReadyCheck is a readiness check endpoint that verifies dependencies
func (a *API) handleReadyCheck(w http.ResponseWriter, r *http.Request) {
	// Check database connectivity
	if err := a.db.Ping(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"not_ready","reason":"database_unavailable"}`))
		return
	}

	// Check k8s connectivity
	if _, _, err := a.getK8sClient(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"not_ready","reason":"kubernetes_unavailable"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
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

// handleTOTPEnroll returns the TOTP secret to the user exactly once (per user),
// after validating a one-time enrollment code and a device-key signature.
func (a *API) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.TOTPEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.DeviceID == "" || req.EnrollmentCode == "" || req.Signature == "" || req.Timestamp == 0 {
		a.jsonError(w, "device_id, enrollment_code, timestamp and signature are required", http.StatusBadRequest)
		return
	}

	// Timestamp window to reduce replay risk.
	now := time.Now().Unix()
	if req.Timestamp < now-300 || req.Timestamp > now+60 {
		a.jsonError(w, "invalid timestamp", http.StatusUnauthorized)
		return
	}

	device, err := a.db.GetDevice(req.DeviceID)
	if err != nil || device == nil {
		a.jsonError(w, "device not found", http.StatusUnauthorized)
		return
	}
	if device.Status != protocol.DeviceStatusApproved {
		a.jsonError(w, "device not approved", http.StatusForbidden)
		return
	}

	// Bind signature to enrollment code to avoid signature reuse with other codes.
	message := fmt.Sprintf("totp_enroll:%d:%s", req.Timestamp, req.EnrollmentCode)
	valid, err := crypto.VerifySignature(device.PublicKey, message, req.Signature)
	if err != nil || !valid {
		a.jsonError(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// Consume enrollment code (one-time), fetch user, and optionally mark TOTP configured.
	userID, err := a.db.ConsumeTOTPEnrollment(hashEnrollmentCode(req.EnrollmentCode), req.DeviceID)
	if err != nil {
		a.jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	// Ensure device is linked to the user (idempotent).
	if device.UserID == "" {
		_ = a.db.SetDeviceUserID(req.DeviceID, userID)
	}

	secret, configured, err := a.db.GetUserTOTPSecret(userID)
	if err != nil {
		a.jsonError(w, "failed to load user TOTP", http.StatusInternalServerError)
		return
	}
	if secret == "" {
		a.jsonError(w, "TOTP not configured for user", http.StatusForbidden)
		return
	}

	// If already configured, do not return the secret again.
	if configured {
		a.jsonResponse(w, &protocol.TOTPEnrollResponse{
			Message: "TOTP already configured for this user",
		}, http.StatusOK)
		return
	}

	accountName := "zcloud"
	if u, err := a.db.GetUser(userID); err == nil && u != nil && u.Name != "" {
		accountName = u.Name
	}
	qr, _ := crypto.GenerateTOTPQRFromSecret(secret, crypto.TOTPConfig{
		Issuer:      a.config.TOTPIssuer,
		AccountName: accountName,
	})
	totpURL := crypto.GetTOTPURL(secret, crypto.TOTPConfig{
		Issuer:      a.config.TOTPIssuer,
		AccountName: accountName,
	})

	// Mark configured before returning the secret to enforce "only once" even under concurrent enrollments.
	marked, err := a.db.MarkUserTOTPConfigured(userID)
	if err != nil {
		a.jsonError(w, "failed to finalize enrollment", http.StatusInternalServerError)
		return
	}
	if !marked {
		// Someone else configured concurrently; do not return the secret again.
		a.jsonResponse(w, &protocol.TOTPEnrollResponse{
			Message: "TOTP already configured for this user",
		}, http.StatusOK)
		return
	}

	a.jsonResponse(w, &protocol.TOTPEnrollResponse{
		Message:    "TOTP enrollment successful",
		TOTPSecret: secret,
		TOTPQR:     qr,
		TOTPURL:    totpURL,
	}, http.StatusOK)
}

func hashEnrollmentCode(code string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(sum[:])
}

func generateEnrollmentCode() string {
	// Human-friendly alphabet (no 0/O, 1/I) for manual typing.
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const n = 12

	var b [n]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Extremely unlikely; fallback to uuid segment (still ok).
		return strings.ToUpper(strings.ReplaceAll(uuid.New().String()[:12], "-", ""))
	}

	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}

	// Group as XXXX-XXXX-XXXX
	return fmt.Sprintf("%s-%s-%s", out[0:4], out[4:8], out[8:12])
}
