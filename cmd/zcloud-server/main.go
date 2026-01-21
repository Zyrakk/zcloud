package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/zyrak/zcloud/internal/server/api"
	"github.com/zyrak/zcloud/internal/server/db"
	"github.com/zyrak/zcloud/internal/shared/crypto"
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
	} `yaml:"kubernetes"`

	Storage struct {
		Database string `yaml:"database"`
	} `yaml:"storage"`
}

func main() {
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
	}
	apiServer := api.New(database, apiConfig)

	// Configurar servidor HTTP
	addr := fmt.Sprintf("%s:%d", config.Server.Host, config.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      apiServer.Router(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
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
	if config.Storage.Database == "" {
		config.Storage.Database = "/opt/zcloud-server/data/zcloud.db"
	}
	if config.Auth.JWTSecretFile == "" {
		config.Auth.JWTSecretFile = "/opt/zcloud-server/data/jwt.secret"
	}

	return &config, nil
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
