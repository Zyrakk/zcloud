package client

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config representa la configuración del cliente
type Config struct {
	Server    ServerConfig  `yaml:"server"`
	Device    DeviceConfig  `yaml:"device"`
	Session   SessionConfig `yaml:"session"`
	Cluster   ClusterConfig `yaml:"cluster"`
	configDir string        `yaml:"-"`
}

// ServerConfig configuración del servidor
type ServerConfig struct {
	URL      string `yaml:"url"`      // https://api.zyrak.cloud
	Insecure bool   `yaml:"insecure"` // Para desarrollo (skip TLS verify)
}

// DeviceConfig configuración del dispositivo
type DeviceConfig struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"name"`
	UserName string `yaml:"user_name,omitempty"` // User/persona name for approval hint
	Approved bool   `yaml:"approved"`
	Trusted  bool   `yaml:"trusted"` // Dispositivo de confianza (TOTP configurado)
}

// SessionConfig configuración de la sesión actual
type SessionConfig struct {
	Token     string    `yaml:"token,omitempty"`
	ExpiresAt time.Time `yaml:"expires_at,omitempty"`
}

// ClusterConfig configuración del cluster
type ClusterConfig struct {
	Name    string `yaml:"name"`    // Nombre para mostrar: "zcloud-homelab"
	Context string `yaml:"context"` // Nombre del contexto: "zcloud"
}

// DefaultConfigDir devuelve el directorio de configuración por defecto
func DefaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".zcloud"
	}
	return filepath.Join(home, ".zcloud")
}

// LoadConfig carga la configuración desde el directorio
func LoadConfig(dir string) (*Config, error) {
	if dir == "" {
		dir = DefaultConfigDir()
	}

	configPath := filepath.Join(dir, "config.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Devolver config vacía si no existe
			return &Config{configDir: dir}, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	cfg.configDir = dir
	return &cfg, nil
}

// Save guarda la configuración
func (c *Config) Save() error {
	if c.configDir == "" {
		c.configDir = DefaultConfigDir()
	}

	// Crear directorio si no existe
	if err := os.MkdirAll(c.configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configPath := filepath.Join(c.configDir, "config.yaml")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// ConfigDir devuelve el directorio de configuración
func (c *Config) ConfigDir() string {
	if c.configDir == "" {
		return DefaultConfigDir()
	}
	return c.configDir
}

// IsInitialized verifica si el cliente está inicializado
func (c *Config) IsInitialized() bool {
	return c.Device.ID != "" && c.Server.URL != ""
}

// IsApproved verifica si el dispositivo está aprobado
func (c *Config) IsApproved() bool {
	return c.Device.Approved
}

// HasValidSession verifica si hay una sesión válida
func (c *Config) HasValidSession() bool {
	if c.Session.Token == "" {
		return false
	}
	return time.Now().Before(c.Session.ExpiresAt)
}

// ClearSession limpia la sesión actual
func (c *Config) ClearSession() {
	c.Session.Token = ""
	c.Session.ExpiresAt = time.Time{}
}

// SetSession establece una nueva sesión
func (c *Config) SetSession(token string, expiresAt time.Time) {
	c.Session.Token = token
	c.Session.ExpiresAt = expiresAt
}

// IsSessionValid verifica si la sesión actual es válida (alias de HasValidSession)
func (c *Config) IsSessionValid() bool {
	return c.HasValidSession()
}

// SessionExpiresIn devuelve cuánto tiempo queda de sesión
func (c *Config) SessionExpiresIn() time.Duration {
	if !c.IsSessionValid() {
		return 0
	}
	return time.Until(c.Session.ExpiresAt)
}
