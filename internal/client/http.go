package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zyrak/zcloud/internal/shared/protocol"
)

// Client representa el cliente HTTP para comunicación con el servidor
type Client struct {
	config     *Config
	httpClient *http.Client
	baseURL    string
}

// NewClient crea un nuevo cliente
func NewClient(config *Config) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.Server.Insecure,
		},
	}

	return &Client{
		config: config,
		httpClient: &http.Client{
			Transport: transport,
		},
		baseURL: config.Server.URL,
	}
}

// doRequest realiza una petición HTTP
func (c *Client) doRequest(method, path string, body interface{}, result interface{}) error {
	// Per-endpoint timeouts (instead of a hard global client timeout) so long-running
	// operations like apply/exec don't get cut at ~30 seconds.
	timeout := 30 * time.Second
	if strings.HasPrefix(path, "/api/v1/exec") || strings.HasPrefix(path, "/api/v1/apply") {
		timeout = 10 * time.Minute
	}

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Añadir token de sesión si existe
	if c.config.HasValidSession() {
		req.Header.Set("Authorization", "Bearer "+c.config.Session.Token)
	}

	// Añadir device ID si existe
	if c.config.Device.ID != "" {
		req.Header.Set("X-Device-ID", c.config.Device.ID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Verificar código de estado
	if resp.StatusCode >= 400 {
		var errResp protocol.ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
			return fmt.Errorf("%s: %s", errResp.Error, errResp.Details)
		}
		return fmt.Errorf("server error: %s (status %d)", string(respBody), resp.StatusCode)
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

// Register registra un nuevo dispositivo
func (c *Client) Register(req *protocol.RegisterRequest) (*protocol.RegisterResponse, error) {
	var resp protocol.RegisterResponse
	if err := c.doRequest("POST", "/api/v1/devices/register", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetDeviceStatus obtiene el estado del dispositivo
func (c *Client) GetDeviceStatus(deviceID string) (*protocol.RegisterResponse, error) {
	var resp protocol.RegisterResponse
	if err := c.doRequest("GET", "/api/v1/devices/status?device_id="+url.QueryEscape(deviceID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EnrollTOTP obtiene el secreto TOTP (una sola vez por usuario) usando un código one-time
// y autenticación por firma de device key.
func (c *Client) EnrollTOTP(req *protocol.TOTPEnrollRequest) (*protocol.TOTPEnrollResponse, error) {
	var resp protocol.TOTPEnrollResponse
	if err := c.doRequest("POST", "/api/v1/totp/enroll", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Login inicia sesión
func (c *Client) Login(req *protocol.LoginRequest) (*protocol.LoginResponse, error) {
	var resp protocol.LoginResponse
	if err := c.doRequest("POST", "/api/v1/auth/login", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Logout cierra la sesión
func (c *Client) Logout() error {
	return c.doRequest("POST", "/api/v1/auth/logout", nil, nil)
}

// GetStatus obtiene el estado del cluster
func (c *Client) GetStatus() (*protocol.StatusResponse, error) {
	var resp protocol.StatusResponse
	if err := c.doRequest("GET", "/api/v1/status/cluster", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Apply aplica manifests de Kubernetes
func (c *Client) Apply(req *protocol.ApplyRequest) (*protocol.ApplyResponse, error) {
	var resp protocol.ApplyResponse
	if err := c.doRequest("POST", "/api/v1/k8s/apply", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Exec ejecuta un comando en el servidor
func (c *Client) Exec(req *protocol.ExecRequest) (*protocol.ExecResponse, error) {
	var resp protocol.ExecResponse
	if err := c.doRequest("POST", "/api/v1/ssh/exec", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListDevices lista todos los dispositivos (admin)
func (c *Client) ListDevices() ([]protocol.DeviceInfo, error) {
	var resp []protocol.DeviceInfo
	if err := c.doRequest("GET", "/api/v1/admin/devices", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// ApproveDevice aprueba un dispositivo (admin) y devuelve el código de enrolamiento TOTP (one-time).
func (c *Client) ApproveDevice(deviceID string, userName string) (*protocol.ApproveDeviceResponse, error) {
	path := "/api/v1/admin/devices/" + deviceID + "/approve"
	if userName != "" {
		path += "?user=" + url.QueryEscape(userName)
	}
	var resp protocol.ApproveDeviceResponse
	if err := c.doRequest("POST", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RevokeDevice revoca un dispositivo (admin)
func (c *Client) RevokeDevice(deviceID string) error {
	return c.doRequest("POST", "/api/v1/admin/devices/"+deviceID+"/revoke", nil, nil)
}

// KubectlProxy hace proxy a un comando kubectl
func (c *Client) KubectlProxy(args []string) (*protocol.ExecResponse, error) {
	req := &protocol.ExecRequest{
		Command: "kubectl",
		Args:    args,
	}
	return c.Exec(req)
}
