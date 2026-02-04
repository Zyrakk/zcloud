package client

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/zyrak/zcloud/internal/shared/crypto"
	"github.com/zyrak/zcloud/internal/shared/protocol"
)

// Auth handles client-side authentication flows.
type Auth struct {
	config  *Config
	client  *Client
	keyPair *crypto.KeyPair
}

// NewAuth creates a new Auth handler.
func NewAuth(config *Config) (*Auth, error) {
	auth := &Auth{
		config: config,
		client: NewClient(config),
	}

	// Load existing keypair if present.
	if config.IsInitialized() {
		kp, err := crypto.LoadFromFiles(config.ConfigDir())
		if err == nil {
			auth.keyPair = kp
		}
	}

	return auth, nil
}

// Init initializes a new device.
func (a *Auth) Init(serverURL string) error {
	// Check if already initialized.
	if a.config.IsInitialized() {
		return fmt.Errorf("configuration already exists in %s\nUse 'zcloud init --reset <server_url>' to re-initialize", a.config.ConfigDir())
	}

	fmt.Println("🔧 ZCloud initial setup")
	fmt.Println()

	// Configure server
	a.config.Server.URL = strings.TrimSuffix(serverURL, "/")
	a.client = NewClient(a.config)

	// Generate keypair
	fmt.Println("   Generating device key pair...")
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}
	a.keyPair = kp

	// Save keys
	if err := kp.SaveToFiles(a.config.ConfigDir()); err != nil {
		return fmt.Errorf("failed to save keys: %w", err)
	}

	// Device name
	hostname, _ := os.Hostname()
	deviceName := promptString(fmt.Sprintf("   Device name [%s]: ", hostname))
	if deviceName == "" {
		deviceName = hostname
	}

	// Register device
	fmt.Println()
	fmt.Println("   Registering device with the server...")

	req := &protocol.RegisterRequest{
		DeviceName: deviceName,
		PublicKey:  kp.PublicKeyString(),
		Hostname:   hostname,
		OS:         runtime.GOOS + "/" + runtime.GOARCH,
	}

	resp, err := a.client.Register(req)
	if err != nil {
		return fmt.Errorf("failed to register device: %w", err)
	}

	// Save config
	a.config.Device.ID = resp.DeviceID
	a.config.Device.Name = deviceName
	a.config.Device.Approved = resp.Status == protocol.DeviceStatusApproved

	if err := a.config.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println()
	fmt.Printf("   🔑 Device ID: %s\n", resp.DeviceID)
	fmt.Println()

	if resp.Status == protocol.DeviceStatusPending {
		fmt.Println("   ⏳ Device registered, awaiting approval")
		fmt.Println()
		fmt.Println("   An admin must approve this device on the server with:")
		fmt.Printf("   zcloud-server admin devices approve %s\n", resp.DeviceID)
		fmt.Println()
		fmt.Println("   Then run: zcloud init --complete")
	} else if resp.Status == protocol.DeviceStatusApproved {
		// Auto-approved (require_approval=false on server)
		a.config.Device.Approved = true
		fmt.Println()
		fmt.Println("   ✅ Device auto-approved")
		if resp.EnrollmentCode != "" {
			fmt.Println()
			fmt.Printf("   🔐 TOTP enrollment code: %s\n", resp.EnrollmentCode)
			fmt.Printf("   ⏰ Expires: %s\n", resp.EnrollmentExpiresAt.Format("2006-01-02 15:04"))
			fmt.Println()
			fmt.Println("   Now set up TOTP with:")
			fmt.Printf("   zcloud totp %s\n", resp.EnrollmentCode)
		} else {
			fmt.Println()
			fmt.Println("   Now you must set up TOTP with: zcloud totp")
		}
	}

	fmt.Println()
	fmt.Printf("   ✅ Configuration saved to %s\n", a.config.ConfigDir())

	return nil
}

// CompleteInit completes initialization after approval.
func (a *Auth) CompleteInit() error {
	if !a.config.IsInitialized() {
		return fmt.Errorf("device not initialized; run 'zcloud init' first")
	}

	if a.config.IsApproved() {
		return fmt.Errorf("device is already approved and configured")
	}

	fmt.Println("🔄 Checking approval status...")

	resp, err := a.client.GetDeviceStatus(a.config.Device.ID)
	if err != nil {
		return fmt.Errorf("failed to get device status: %w", err)
	}

	if resp.Status == protocol.DeviceStatusPending {
		return fmt.Errorf("device is still pending approval")
	}

	if resp.Status == protocol.DeviceStatusRevoked {
		return fmt.Errorf("device has been revoked")
	}

	fmt.Println()
	fmt.Println("   ✅ Device approved")
	fmt.Println()

	a.config.Device.Approved = true
	if err := a.config.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println("   🎉 Setup complete!")
	fmt.Println()
	fmt.Println("   Now set up TOTP with: zcloud totp")
	fmt.Println("   Then you can log in with: zcloud login")

	return nil
}

// SetupTOTP configures TOTP for a user/persona (one-time) using an enrollment code.
func (a *Auth) SetupTOTP(enrollmentCode string) error {
	if !a.config.IsInitialized() {
		return fmt.Errorf("device not initialized; run 'zcloud init' first")
	}

	if !a.config.IsApproved() {
		return fmt.Errorf("device not approved; run 'zcloud init --complete' first")
	}

	fmt.Println("🔐 TOTP setup")
	fmt.Printf("   Device: %s (%s)\n", a.config.Device.Name, safePrefix(a.config.Device.ID, 8))
	fmt.Println()

	if strings.TrimSpace(enrollmentCode) == "" {
		fmt.Print("   Enter the enrollment code (e.g. ABCD-EFGH-IJKL): ")
		enrollmentCode = promptString("")
	}

	// Cargar keypair
	if a.keyPair == nil {
		kp, err := crypto.LoadFromFiles(a.config.ConfigDir())
		if err != nil {
			return fmt.Errorf("failed to load keys: %w", err)
		}
		a.keyPair = kp
	}

	timestamp := time.Now().Unix()
	msgToSign := fmt.Sprintf("totp_enroll:%d:%s", timestamp, strings.TrimSpace(enrollmentCode))
	signature := a.keyPair.Sign([]byte(msgToSign))

	enrollResp, err := a.client.EnrollTOTP(&protocol.TOTPEnrollRequest{
		DeviceID:       a.config.Device.ID,
		Timestamp:      timestamp,
		Signature:      signature,
		EnrollmentCode: strings.TrimSpace(enrollmentCode),
	})
	if err != nil {
		return fmt.Errorf("failed to enroll TOTP: %w", err)
	}

	if enrollResp.TOTPSecret == "" {
		// Typical case for devices belonging to a user that already configured TOTP earlier.
		if enrollResp.Message != "" {
			fmt.Println("   ✅ " + enrollResp.Message)
		} else {
			fmt.Println("   ✅ TOTP is already configured for this user")
		}
		return nil
	}

	fmt.Println("   Configure your TOTP app (Google Authenticator, Aegis, etc.):")
	fmt.Println()
	fmt.Printf("   Secret: %s\n", enrollResp.TOTPSecret)
	fmt.Println()

	if enrollResp.TOTPQR != "" {
		fmt.Println("   (QR code available in base64 - use the manual secret above)")
	}

	// Verificar que el TOTP funciona
	fmt.Println()
	fmt.Print("   Enter a TOTP code to verify: ")
	code := readTOTP()

	if !crypto.ValidateTOTP(enrollResp.TOTPSecret, code) {
		return fmt.Errorf("invalid TOTP code")
	}

	fmt.Println()
	fmt.Println("   ✅ TOTP configured successfully")
	fmt.Println()
	fmt.Println("   You can now log in with: zcloud login")

	// Marcar el dispositivo como trusted (UX)
	if !a.config.Device.Trusted {
		a.config.Device.Trusted = true
		_ = a.config.Save()
	}

	return nil
}

// Login performs an interactive login (prompts for TOTP).
func (a *Auth) Login() error {
	if !a.config.IsInitialized() {
		return fmt.Errorf("device not initialized; run 'zcloud init' first")
	}

	if !a.config.IsApproved() {
		return fmt.Errorf("device not approved; run 'zcloud init --complete'")
	}

	if a.config.HasValidSession() {
		return nil
	}

	// Cargar keypair
	if a.keyPair == nil {
		kp, err := crypto.LoadFromFiles(a.config.ConfigDir())
		if err != nil {
			return fmt.Errorf("failed to load keys: %w", err)
		}
		a.keyPair = kp
	}

	// Prompt for TOTP (no echo if possible)
	fmt.Print("🔑 TOTP: ")
	totpCode := readTOTP()

	// Crear firma del timestamp
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%d", timestamp)
	signature := a.keyPair.Sign([]byte(message))

	// Hacer login
	req := &protocol.LoginRequest{
		DeviceID:  a.config.Device.ID,
		Timestamp: timestamp,
		Signature: signature,
		TOTPCode:  totpCode,
	}

	resp, err := a.client.Login(req)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	// Guardar sesión
	a.config.SetSession(resp.Token, resp.ExpiresAt)
	if err := a.config.Save(); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	return nil
}

// Logout logs out (best-effort server revoke) and clears local session.
func (a *Auth) Logout() error {
	if !a.config.HasValidSession() {
		return nil
	}

	// Notificar al servidor
	_ = a.client.Logout() // Ignorar errores

	// Limpiar sesión local
	a.config.ClearSession()
	if err := a.config.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

// Status prints current status.
func (a *Auth) Status() error {
	fmt.Println()

	if !a.config.IsInitialized() {
		fmt.Println("❌ Device not initialized")
		fmt.Println("   Run: zcloud init <server_url>")
		return nil
	}

	fmt.Printf("📱 Device:  %s (%s)\n", a.config.Device.Name, safePrefix(a.config.Device.ID, 8))
	fmt.Printf("🌐 Server:  %s\n", a.config.Server.URL)

	if !a.config.IsApproved() {
		fmt.Println("⏳ Status:  pending approval")
		return nil
	}

	if !a.config.HasValidSession() {
		fmt.Println("🔒 Session: not active")
		fmt.Println("   Run: zcloud login")
		return nil
	}

	fmt.Printf("✅ Session: active (until %s)\n", a.config.Session.ExpiresAt.Format("15:04"))

	// Obtener estado del cluster
	status, err := a.client.GetStatus()
	if err != nil {
		fmt.Printf("⚠️  Cluster: error: %v\n", err)
		return nil
	}

	fmt.Println()
	fmt.Printf("☸️  Cluster: %s\n", status.ClusterName)
	fmt.Println()
	fmt.Println("   NODES")
	for _, node := range status.Nodes {
		statusIcon := "✅"
		if node.Status != "Ready" {
			statusIcon = "❌"
		}
		fmt.Printf("   ├─ %-12s %-15s %s\n", node.Name, node.Role, statusIcon)
	}

	return nil
}

// EnsureSession ensures there is a valid session.
func (a *Auth) EnsureSession() error {
	if !a.config.HasValidSession() {
		return fmt.Errorf("no active session; run 'zcloud login'")
	}
	return nil
}

// GetClient devuelve el cliente HTTP
func (a *Auth) GetClient() *Client {
	return a.client
}

func safePrefix(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Helper functions

func promptString(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func readTOTP() string {
	// Leer sin echo si es posible
	if term.IsTerminal(int(os.Stdin.Fd())) {
		bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err == nil {
			return strings.TrimSpace(string(bytepw))
		}
	}
	// Fallback a lectura normal
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// ParseDuration parsea una duración como "12h" o "30m"
func ParseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "h") {
		hours, err := strconv.Atoi(strings.TrimSuffix(s, "h"))
		if err != nil {
			return 0, err
		}
		return time.Duration(hours) * time.Hour, nil
	}
	if strings.HasSuffix(s, "m") {
		mins, err := strconv.Atoi(strings.TrimSuffix(s, "m"))
		if err != nil {
			return 0, err
		}
		return time.Duration(mins) * time.Minute, nil
	}
	return time.ParseDuration(s)
}
