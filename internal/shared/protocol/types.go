package protocol

import "time"

// DeviceStatus representa el estado de un dispositivo
type DeviceStatus string

const (
	DeviceStatusPending  DeviceStatus = "pending"
	DeviceStatusApproved DeviceStatus = "approved"
	DeviceStatusRevoked  DeviceStatus = "revoked"
)

// RegisterRequest - solicitud de registro de dispositivo
type RegisterRequest struct {
	DeviceName string `json:"device_name"`
	PublicKey  string `json:"public_key"` // Ed25519 public key (base64)
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
}

// RegisterResponse - respuesta al registro
type RegisterResponse struct {
	DeviceID  string       `json:"device_id"`
	Status    DeviceStatus `json:"status"`
	Message   string       `json:"message,omitempty"`
	TOTPSecret string      `json:"totp_secret,omitempty"` // Solo cuando approved
	TOTPQR     string      `json:"totp_qr,omitempty"`     // QR en base64
}

// LoginRequest - solicitud de login
type LoginRequest struct {
	DeviceID  string `json:"device_id"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"` // Firma del timestamp con device key
	TOTPCode  string `json:"totp_code"`
}

// LoginResponse - respuesta al login
type LoginResponse struct {
	Token     string    `json:"token"`      // JWT
	ExpiresAt time.Time `json:"expires_at"`
	Message   string    `json:"message,omitempty"`
}

// StatusResponse - respuesta de estado del cluster
type StatusResponse struct {
	Connected   bool        `json:"connected"`
	ClusterName string      `json:"cluster_name"`
	Nodes       []NodeInfo  `json:"nodes"`
	Session     SessionInfo `json:"session"`
}

// NodeInfo - información de un nodo
type NodeInfo struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Status string `json:"status"`
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// SessionInfo - información de la sesión actual
type SessionInfo struct {
	DeviceID  string    `json:"device_id"`
	DeviceName string   `json:"device_name"`
	ExpiresAt time.Time `json:"expires_at"`
	Valid     bool      `json:"valid"`
}

// DeviceInfo - información completa de un dispositivo (admin)
type DeviceInfo struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	PublicKey  string       `json:"public_key"`
	Hostname   string       `json:"hostname"`
	OS         string       `json:"os"`
	Status     DeviceStatus `json:"status"`
	CreatedAt  time.Time    `json:"created_at"`
	LastAccess time.Time    `json:"last_access,omitempty"`
}

// ErrorResponse - respuesta de error genérica
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// ApplyRequest - solicitud para aplicar manifests
type ApplyRequest struct {
	Manifests []string `json:"manifests"` // YAML contents
	Namespace string   `json:"namespace,omitempty"`
	DryRun    bool     `json:"dry_run,omitempty"`
}

// ApplyResponse - respuesta de aplicar manifests
type ApplyResponse struct {
	Results []ApplyResult `json:"results"`
	Success bool          `json:"success"`
}

// ApplyResult - resultado de aplicar un manifest
type ApplyResult struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Action    string `json:"action"` // created, configured, unchanged
	Error     string `json:"error,omitempty"`
}

// ExecRequest - solicitud de ejecución de comando
type ExecRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	WorkDir string   `json:"workdir,omitempty"`
}

// ExecResponse - respuesta de ejecución
type ExecResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

// ================== SSH Protocol Types ==================

// SSHMessageType tipos de mensajes WebSocket para SSH
type SSHMessageType string

const (
	SSHMessageInput  SSHMessageType = "input"  // Input del usuario
	SSHMessageOutput SSHMessageType = "output" // Output del shell
	SSHMessageResize SSHMessageType = "resize" // Cambio de tamaño de terminal
	SSHMessageError  SSHMessageType = "error"  // Error
	SSHMessageClose  SSHMessageType = "close"  // Cerrar conexión
)

// SSHMessage mensaje genérico para comunicación WebSocket SSH
type SSHMessage struct {
	Type SSHMessageType `json:"type"`
	Data []byte         `json:"data,omitempty"`
	Rows uint16         `json:"rows,omitempty"`
	Cols uint16         `json:"cols,omitempty"`
}

// ================== File Transfer Types ==================

// FileUploadRequest - solicitud de subida de archivo
type FileUploadRequest struct {
	Path     string `json:"path"`
	Mode     uint32 `json:"mode,omitempty"`     // Permisos del archivo
	Checksum string `json:"checksum,omitempty"` // SHA256 opcional
}

// FileUploadResponse - respuesta de subida
type FileUploadResponse struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Checksum string `json:"checksum"`
	Message  string `json:"message,omitempty"`
}

// FileDownloadRequest - solicitud de descarga
type FileDownloadRequest struct {
	Path string `json:"path"`
}

// FileInfo - información de un archivo
type FileInfo struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"mod_time"`
	IsDir   bool      `json:"is_dir"`
}

// FileListRequest - solicitud para listar archivos
type FileListRequest struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive,omitempty"`
}

// FileListResponse - respuesta de listar archivos
type FileListResponse struct {
	Files []FileInfo `json:"files"`
	Path  string     `json:"path"`
}
