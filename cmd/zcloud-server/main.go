package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/zyrak/zcloud/internal/server/api"
	"github.com/zyrak/zcloud/internal/server/db"
	"github.com/zyrak/zcloud/internal/shared/crypto"
	"github.com/zyrak/zcloud/internal/shared/protocol"
)

// ServerConfig configuración del servidor desde YAML
type ServerConfig struct {
	Server struct {
		Host   string `yaml:"host"`
		Port   int    `yaml:"port"`
		Domain string `yaml:"domain"`
	} `yaml:"server"`

	TLS struct {
		Cert      string `yaml:"cert"`
		Key       string `yaml:"key"`
		AutoRenew bool   `yaml:"auto_renew"`
	} `yaml:"tls"`

	Auth struct {
		JWTSecretFile   string `yaml:"jwt_secret_file"`
		SessionTTL      string `yaml:"session_ttl"`
		TOTPIssuer      string `yaml:"totp_issuer"`
		RequireApproval bool   `yaml:"require_approval"`
	} `yaml:"auth"`

	Kubernetes struct {
		Kubeconfig string `yaml:"kubeconfig"`
		CoreDNSIP  string `yaml:"coredns_ip"`
		CACert     string `yaml:"ca_cert"`
	} `yaml:"kubernetes"`

	Storage struct {
		Database string `yaml:"database"`
	} `yaml:"storage"`
}

func main() {
	// Check for admin subcommand first (before flag parsing)
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		runAdminCommand()
		return
	}

	configPath := flag.String("config", "/opt/zcloud-server/config.yaml", "Path to config file")
	initMode := flag.Bool("init", false, "Initialize server configuration")
	flag.Parse()

	// Inicialización
	if *initMode {
		if err := initServer(*configPath); err != nil {
			log.Fatalf("Failed to initialize server: %v", err)
		}
		return
	}

	// Cargar configuración
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Validar configuración
	if errs := validateConfig(config); len(errs) > 0 {
		log.Println("❌ Configuration errors:")
		for _, e := range errs {
			log.Printf("  - %s", e)
		}
		log.Fatal("Please fix configuration errors before starting server")
	}

	// Cargar JWT secret
	jwtSecret, err := loadOrCreateJWTSecret(config.Auth.JWTSecretFile)
	if err != nil {
		log.Fatalf("Failed to load JWT secret: %v", err)
	}

	// Parsear session TTL
	sessionTTL, err := time.ParseDuration(config.Auth.SessionTTL)
	if err != nil {
		sessionTTL = 12 * time.Hour
	}

	// Conectar a la base de datos
	database, err := db.New(config.Storage.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Crear API
	apiConfig := &api.Config{
		JWTSecret:       jwtSecret,
		SessionTTL:      sessionTTL,
		TOTPIssuer:      config.Auth.TOTPIssuer,
		RequireApproval: config.Auth.RequireApproval,
		KubeconfigPath:  config.Kubernetes.Kubeconfig,
		CoreDNSIP:       config.Kubernetes.CoreDNSIP,
		CACertPath:      config.Kubernetes.CACert,
	}
	apiServer := api.New(database, apiConfig)

	// Configurar servidor HTTP
	addr := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
	server := &http.Server{
		Addr:        addr,
		Handler:     apiServer.Router(),
		ReadTimeout: 30 * time.Second,
		// WriteTimeout must be 0 to support long-lived connections like kubectl watch/exec/logs
		// The k8s proxy handler manages timeouts per-request for non-streaming requests
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	// TLS si está configurado
	if config.TLS.Cert != "" && config.TLS.Key != "" {
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		}
	}

	// Limpieza de sesiones expiradas cada hora
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := database.CleanExpiredSessions(); err != nil {
				log.Printf("Failed to clean expired sessions: %v", err)
			}
		}
	}()

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down server...")
		server.Close()
	}()

	// Iniciar servidor
	log.Printf("Starting zcloud-server on %s", addr)

	if config.TLS.Cert != "" && config.TLS.Key != "" {
		log.Printf("TLS enabled with cert: %s", config.TLS.Cert)
		if err := server.ListenAndServeTLS(config.TLS.Cert, config.TLS.Key); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	} else {
		log.Println("WARNING: TLS not configured, running in HTTP mode")
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}

	log.Println("Server stopped")
}

func loadConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config ServerConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Valores por defecto
	if config.Server.Host == "" {
		config.Server.Host = "0.0.0.0"
	}
	if config.Server.Port == 0 {
		config.Server.Port = 8443
	}
	if config.Auth.SessionTTL == "" {
		config.Auth.SessionTTL = "12h"
	}
	if config.Auth.TOTPIssuer == "" {
		config.Auth.TOTPIssuer = "ZCloud"
	}
	if config.Kubernetes.Kubeconfig == "" {
		config.Kubernetes.Kubeconfig = "/etc/rancher/k3s/k3s.yaml"
	}
	if config.Kubernetes.CoreDNSIP == "" {
		config.Kubernetes.CoreDNSIP = "10.43.0.10:53"
	}
	if config.Kubernetes.CACert == "" {
		// Try common k3s CA locations
		commonPaths := []string{
			"/var/lib/rancher/k3s/server/tls/server-ca.crt",
			"/etc/rancher/k3s/k3s.yaml", // Will extract from kubeconfig if needed
		}
		for _, path := range commonPaths {
			if _, err := os.Stat(path); err == nil {
				if path != "/etc/rancher/k3s/k3s.yaml" {
					config.Kubernetes.CACert = path
					break
				}
			}
		}
	}
	if config.Storage.Database == "" {
		config.Storage.Database = "/opt/zcloud-server/data/zcloud.db"
	}
	if config.Auth.JWTSecretFile == "" {
		config.Auth.JWTSecretFile = "/opt/zcloud-server/data/jwt.secret"
	}

	return &config, nil
}

// validateConfig checks the configuration for errors and warnings
func validateConfig(config *ServerConfig) []string {
	var errors []string

	// Validate server configuration
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		errors = append(errors, "Invalid server port: must be between 1 and 65535")
	}
	if config.Server.Host == "" {
		errors = append(errors, "Server host cannot be empty")
	}

	// Validate TLS configuration
	if config.TLS.Cert != "" && config.TLS.Key == "" {
		errors = append(errors, "TLS key specified but cert is missing")
	}
	if config.TLS.Key != "" && config.TLS.Cert == "" {
		errors = append(errors, "TLS cert specified but key is missing")
	}
	if config.TLS.Cert != "" {
		if _, err := os.Stat(config.TLS.Cert); os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("TLS cert file not found: %s", config.TLS.Cert))
		}
	}
	if config.TLS.Key != "" {
		if _, err := os.Stat(config.TLS.Key); os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("TLS key file not found: %s", config.TLS.Key))
		}
	}

	// Validate auth configuration
	if config.Auth.SessionTTL != "" {
		if _, err := time.ParseDuration(config.Auth.SessionTTL); err != nil {
			errors = append(errors, fmt.Sprintf("Invalid session_ttl: %s", config.Auth.SessionTTL))
		}
	}
	if config.Auth.TOTPIssuer == "" {
		errors = append(errors, "TOTP issuer cannot be empty")
	}
	if config.Auth.JWTSecretFile == "" {
		errors = append(errors, "JWT secret file path cannot be empty")
	}

	// Validate Kubernetes configuration
	if config.Kubernetes.Kubeconfig != "" {
		if _, err := os.Stat(config.Kubernetes.Kubeconfig); os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("Kubeconfig file not found: %s", config.Kubernetes.Kubeconfig))
		}
	}
	if config.Kubernetes.CoreDNSIP != "" {
		host, port, err := net.SplitHostPort(config.Kubernetes.CoreDNSIP)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Invalid CoreDNS IP:port: %s", config.Kubernetes.CoreDNSIP))
		} else if host == "" || port == "" {
			errors = append(errors, fmt.Sprintf("Invalid CoreDNS IP:port: %s", config.Kubernetes.CoreDNSIP))
		}
	}
	if config.Kubernetes.CACert != "" {
		if _, err := os.Stat(config.Kubernetes.CACert); os.IsNotExist(err) {
			errors = append(errors, fmt.Sprintf("CA cert file not found: %s", config.Kubernetes.CACert))
		}
	}

	// Validate storage configuration
	if config.Storage.Database == "" {
		errors = append(errors, "Database path cannot be empty")
	}
	
	// Check parent directory exists for database
	dbDir := filepath.Dir(config.Storage.Database)
	if _, err := os.Stat(dbDir); os.IsNotExist(err) {
		errors = append(errors, fmt.Sprintf("Database directory does not exist: %s", dbDir))
	}

	return errors
}

func loadOrCreateJWTSecret(path string) (string, error) {
	// Crear directorio si no existe
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}

	// Intentar leer secret existente
	data, err := os.ReadFile(path)
	if err == nil {
		return string(data), nil
	}

	// Generar nuevo secret
	secret, err := crypto.GenerateRandomSecret(32)
	if err != nil {
		return "", err
	}

	// Guardar
	if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
		return "", err
	}

	log.Printf("Generated new JWT secret at %s", path)
	return secret, nil
}

func initServer(configPath string) error {
	fmt.Println("🔧 Inicializando zcloud-server...")

	// Crear directorios
	dirs := []string{
		"/opt/zcloud-server/data",
		"/opt/zcloud-server/certs",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Crear config por defecto si no existe
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		defaultConfig := `# ZCloud Server Configuration
server:
  host: 0.0.0.0
  port: 443
  domain: api.zyrak.cloud

tls:
  cert: /opt/zcloud-server/certs/fullchain.pem
  key: /opt/zcloud-server/certs/privkey.pem
  auto_renew: true

auth:
  jwt_secret_file: /opt/zcloud-server/data/jwt.secret
  session_ttl: 12h
  totp_issuer: "ZCloud"
  require_approval: true

 kubernetes:
  kubeconfig: /etc/rancher/k3s/k3s.yaml
  coredns_ip: 10.43.0.10:53
  ca_cert: /var/lib/rancher/k3s/server/tls/server-ca.crt

 storage:
  database: /opt/zcloud-server/data/zcloud.db
`
		if err := os.WriteFile(configPath, []byte(defaultConfig), 0600); err != nil {
			return fmt.Errorf("failed to write config: %w", err)
		}
		fmt.Printf("✅ Configuración creada en %s\n", configPath)
	}

	// Crear JWT secret
	jwtSecretPath := "/opt/zcloud-server/data/jwt.secret"
	if _, err := os.Stat(jwtSecretPath); os.IsNotExist(err) {
		secret, err := crypto.GenerateRandomSecret(32)
		if err != nil {
			return fmt.Errorf("failed to generate JWT secret: %w", err)
		}
		if err := os.WriteFile(jwtSecretPath, []byte(secret), 0600); err != nil {
			return fmt.Errorf("failed to write JWT secret: %w", err)
		}
		fmt.Println("✅ JWT secret generado")
	}

	// Crear base de datos
	dbPath := "/opt/zcloud-server/data/zcloud.db"
	database, err := db.New(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	database.Close()
	fmt.Println("✅ Base de datos creada")

	fmt.Println()
	fmt.Println("📋 Próximos pasos:")
	fmt.Println("   1. Edita la configuración: /opt/zcloud-server/config.yaml")
	fmt.Println("   2. Configura certificados TLS (Let's Encrypt):")
	fmt.Println("      certbot certonly --standalone -d api.zyrak.cloud")
	fmt.Println("   3. Habilita el servicio:")
	fmt.Println("      systemctl enable --now zcloud-server")
	fmt.Println()

	return nil
}

// runAdminCommand handles direct database administration commands
func runAdminCommand() {
	// Usage: zcloud-server admin devices <list|approve|revoke> [device_id] [--config path]
	if len(os.Args) < 3 {
		printAdminUsage()
		os.Exit(1)
	}

	// Parse config flag from remaining args
	configPath := "/opt/zcloud-server/config.yaml"
	for i, arg := range os.Args {
		if arg == "--config" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
			break
		}
	}

	// Load config to get database path
	config, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Connect to database
	database, err := db.New(config.Storage.Database)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()

	subcommand := os.Args[2]
	if subcommand != "devices" {
		fmt.Fprintf(os.Stderr, "Unknown admin subcommand: %s\n", subcommand)
		printAdminUsage()
		os.Exit(1)
	}

	if len(os.Args) < 4 {
		printAdminUsage()
		os.Exit(1)
	}

	action := os.Args[3]

	switch action {
	case "list":
		adminListDevices(database)
	case "approve":
		if len(os.Args) < 5 {
			fmt.Fprintln(os.Stderr, "Error: device_id required")
			fmt.Fprintln(os.Stderr, "Usage: zcloud-server admin devices approve <device_id>")
			os.Exit(1)
		}
		adminApproveDevice(database, os.Args[4], config)
	case "revoke":
		if len(os.Args) < 5 {
			fmt.Fprintln(os.Stderr, "Error: device_id required")
			fmt.Fprintln(os.Stderr, "Usage: zcloud-server admin devices revoke <device_id>")
			os.Exit(1)
		}
		adminRevokeDevice(database, os.Args[4])
	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s\n", action)
		printAdminUsage()
		os.Exit(1)
	}
}

func printAdminUsage() {
	fmt.Println("Usage: zcloud-server admin devices <command> [device_id] [--config path]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  list              List all registered devices")
	fmt.Println("  approve <id>      Approve a pending device")
	fmt.Println("  revoke <id>       Revoke a device")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --config path     Path to config file (default: /opt/zcloud-server/config.yaml)")
}

func adminListDevices(database *db.Database) {
	devices, err := database.ListDevices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing devices: %v\n", err)
		os.Exit(1)
	}

	if len(devices) == 0 {
		fmt.Println("No devices registered")
		return
	}

	fmt.Println()
	fmt.Printf("%-14s %-15s %-10s %-20s\n", "ID", "NAME", "STATUS", "CREATED")
	fmt.Println(strings.Repeat("-", 65))

	for _, d := range devices {
		fmt.Printf("%-14s %-15s %-10s %-20s\n",
			d.ID[:12],
			truncate(d.Name, 15),
			d.Status,
			d.CreatedAt.Format("2006-01-02 15:04"))
	}
	fmt.Println()
}

func adminApproveDevice(database *db.Database, deviceID string, config *ServerConfig) {
	// Find device (support partial ID)
	device, err := findDevice(database, deviceID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if device.Status == protocol.DeviceStatusApproved {
		fmt.Printf("Device %s is already approved\n", device.ID[:12])
		return
	}

	// Update status to approved
	if err := database.UpdateDeviceStatus(device.ID, protocol.DeviceStatusApproved); err != nil {
		fmt.Fprintf(os.Stderr, "Error approving device: %v\n", err)
		os.Exit(1)
	}

	// Generate TOTP secret
	totpSecret, _, err := crypto.GenerateTOTP(crypto.TOTPConfig{
		Issuer:      config.Auth.TOTPIssuer,
		AccountName: device.Name,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating TOTP: %v\n", err)
		os.Exit(1)
	}

	if err := database.UpdateDeviceTOTP(device.ID, totpSecret); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving TOTP: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Device approved: %s (%s)\n", device.Name, device.ID[:12])
	fmt.Println()
	fmt.Println("The client must now run: zcloud totp")
}

func adminRevokeDevice(database *db.Database, deviceID string) {
	device, err := findDevice(database, deviceID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := database.UpdateDeviceStatus(device.ID, protocol.DeviceStatusRevoked); err != nil {
		fmt.Fprintf(os.Stderr, "Error revoking device: %v\n", err)
		os.Exit(1)
	}

	// Delete active sessions
	_ = database.DeleteDeviceSessions(device.ID)

	fmt.Printf("✅ Device revoked: %s (%s)\n", device.Name, device.ID[:12])
}

func findDevice(database *db.Database, partialID string) (*protocol.DeviceInfo, error) {
	devices, err := database.ListDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}

	var matches []protocol.DeviceInfo
	for _, d := range devices {
		if strings.HasPrefix(d.ID, partialID) {
			matches = append(matches, d)
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("device not found: %s", partialID)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("ambiguous device ID: %s (matches %d devices)", partialID, len(matches))
	}

	return &matches[0], nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
