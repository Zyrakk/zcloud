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

// Auth maneja la autenticación del cliente
type Auth struct {
	config  *Config
	client  *Client
	keyPair *crypto.KeyPair
}

// NewAuth crea un nuevo manejador de autenticación
func NewAuth(config *Config) (*Auth, error) {
	auth := &Auth{
		config: config,
		client: NewClient(config),
	}

	// Cargar keypair si existe
	if config.IsInitialized() {
		kp, err := crypto.LoadFromFiles(config.ConfigDir())
		if err == nil {
			auth.keyPair = kp
		}
	}

	return auth, nil
}

// Init inicializa un nuevo dispositivo
func (a *Auth) Init(serverURL string) error {
	// Verificar si ya está inicializado
	if a.config.IsInitialized() {
		return fmt.Errorf("ya existe una configuración en %s\nUsa 'zcloud reset' para reiniciar", a.config.ConfigDir())
	}

	fmt.Println("🔧 Configuración inicial de zcloud")
	fmt.Println()

	// Configurar servidor
	a.config.Server.URL = strings.TrimSuffix(serverURL, "/")
	a.client = NewClient(a.config)

	// Generar keypair
	fmt.Println("   Generando par de claves del dispositivo...")
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}
	a.keyPair = kp

	// Guardar claves
	if err := kp.SaveToFiles(a.config.ConfigDir()); err != nil {
		return fmt.Errorf("failed to save keys: %w", err)
	}

	// Obtener nombre del dispositivo
	hostname, _ := os.Hostname()
	deviceName := promptString(fmt.Sprintf("   Nombre del dispositivo [%s]: ", hostname))
	if deviceName == "" {
		deviceName = hostname
	}

	// Registrar dispositivo
	fmt.Println()
	fmt.Println("   Registrando dispositivo en el servidor...")

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

	// Guardar configuración
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
		fmt.Println("   ⏳ Dispositivo registrado, pendiente de aprobación")
		fmt.Println()
		fmt.Println("   El administrador debe aprobar este dispositivo con:")
		fmt.Printf("   zcloud admin devices approve %s\n", resp.DeviceID)
		fmt.Println()
		fmt.Println("   Después ejecuta: zcloud init --complete")
	} else if resp.Status == protocol.DeviceStatusApproved {
		return a.completeSetup(resp)
	}

	fmt.Println()
	fmt.Printf("   ✅ Configuración guardada en %s\n", a.config.ConfigDir())

	return nil
}

// CompleteInit completa la inicialización después de la aprobación
func (a *Auth) CompleteInit() error {
	if !a.config.IsInitialized() {
		return fmt.Errorf("dispositivo no inicializado, ejecuta 'zcloud init' primero")
	}

	if a.config.IsApproved() {
		return fmt.Errorf("dispositivo ya está aprobado y configurado")
	}

	fmt.Println("🔄 Verificando estado de aprobación...")

	resp, err := a.client.GetDeviceStatus(a.config.Device.ID)
	if err != nil {
		return fmt.Errorf("failed to get device status: %w", err)
	}

	if resp.Status == protocol.DeviceStatusPending {
		return fmt.Errorf("dispositivo aún pendiente de aprobación")
	}

	if resp.Status == protocol.DeviceStatusRevoked {
		return fmt.Errorf("dispositivo ha sido revocado")
	}

	return a.completeSetup(resp)
}

// completeSetup completa la configuración con TOTP
func (a *Auth) completeSetup(resp *protocol.RegisterResponse) error {
	fmt.Println()
	fmt.Println("   ✅ Dispositivo aprobado")
	fmt.Println()

	if resp.TOTPSecret != "" {
		fmt.Println("   Configura tu aplicación TOTP (Google Authenticator, Authy, etc.):")
		fmt.Println()
		fmt.Printf("   Secret: %s\n", resp.TOTPSecret)
		fmt.Println()

		// Mostrar QR si está disponible
		if resp.TOTPQR != "" {
			// El QR está en base64, podríamos mostrarlo en terminal
			// pero es más fácil que el usuario use el secret directamente
			fmt.Println("   (QR code disponible - usa el secret manual arriba)")
		}

		// Verificar que el TOTP funciona
		fmt.Println()
		fmt.Print("   Introduce el código TOTP para verificar: ")
		code := readTOTP()

		if !crypto.ValidateTOTP(resp.TOTPSecret, code) {
			return fmt.Errorf("código TOTP inválido")
		}

		fmt.Println("   ✅ TOTP configurado correctamente")
	}

	a.config.Device.Approved = true
	if err := a.config.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println()
	fmt.Println("   🎉 Configuración completa!")
	fmt.Println()
	fmt.Println("   Ahora puedes iniciar sesión con: zcloud login")

	return nil
}

// Login inicia sesión
func (a *Auth) Login() error {
	if !a.config.IsInitialized() {
		return fmt.Errorf("dispositivo no inicializado, ejecuta 'zcloud init' primero")
	}

	if !a.config.IsApproved() {
		return fmt.Errorf("dispositivo no aprobado, ejecuta 'zcloud init --complete'")
	}

	if a.config.HasValidSession() {
		fmt.Printf("✅ Sesión activa (válida hasta %s)\n", a.config.Session.ExpiresAt.Format("15:04"))
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

	fmt.Printf("🔐 Device: %s (%s)\n", a.config.Device.Name, a.config.Device.ID[:8])

	// Pedir código TOTP
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

	fmt.Printf("✅ Sesión iniciada (válida hasta %s)\n", resp.ExpiresAt.Format("15:04"))

	return nil
}

// Logout cierra la sesión
func (a *Auth) Logout() error {
	if !a.config.HasValidSession() {
		fmt.Println("No hay sesión activa")
		return nil
	}

	// Notificar al servidor
	_ = a.client.Logout() // Ignorar errores

	// Limpiar sesión local
	a.config.ClearSession()
	if err := a.config.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println("👋 Sesión cerrada")
	return nil
}

// Status muestra el estado actual
func (a *Auth) Status() error {
	fmt.Println()

	if !a.config.IsInitialized() {
		fmt.Println("❌ Dispositivo no inicializado")
		fmt.Println("   Ejecuta: zcloud init <server_url>")
		return nil
	}

	fmt.Printf("📱 Dispositivo: %s (%s)\n", a.config.Device.Name, a.config.Device.ID[:8])
	fmt.Printf("🌐 Servidor:    %s\n", a.config.Server.URL)

	if !a.config.IsApproved() {
		fmt.Println("⏳ Estado:      Pendiente de aprobación")
		return nil
	}

	if !a.config.HasValidSession() {
		fmt.Println("🔒 Sesión:      No activa")
		fmt.Println("   Ejecuta: zcloud login")
		return nil
	}

	fmt.Printf("✅ Sesión:      Activa (hasta %s)\n", a.config.Session.ExpiresAt.Format("15:04"))

	// Obtener estado del cluster
	status, err := a.client.GetStatus()
	if err != nil {
		fmt.Printf("⚠️  Cluster:     Error: %v\n", err)
		return nil
	}

	fmt.Println()
	fmt.Printf("☸️  Cluster:     %s\n", status.ClusterName)
	fmt.Println()
	fmt.Println("   NODOS")
	for _, node := range status.Nodes {
		statusIcon := "✅"
		if node.Status != "Ready" {
			statusIcon = "❌"
		}
		fmt.Printf("   ├─ %-12s %-15s %s\n", node.Name, node.Role, statusIcon)
	}

	return nil
}

// EnsureSession verifica que hay una sesión válida
func (a *Auth) EnsureSession() error {
	if !a.config.HasValidSession() {
		return fmt.Errorf("no hay sesión activa, ejecuta 'zcloud login'")
	}
	return nil
}

// GetClient devuelve el cliente HTTP
func (a *Auth) GetClient() *Client {
	return a.client
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
