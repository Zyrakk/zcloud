package client

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// KubeConfig estructura del kubeconfig
type KubeConfig struct {
	APIVersion     string         `yaml:"apiVersion"`
	Kind           string         `yaml:"kind"`
	Preferences    map[string]any `yaml:"preferences"`
	Clusters       []KubeCluster  `yaml:"clusters"`
	Contexts       []KubeContext  `yaml:"contexts"`
	CurrentContext string         `yaml:"current-context"`
	Users          []KubeUser     `yaml:"users"`
}

// KubeCluster representa un cluster en kubeconfig
type KubeCluster struct {
	Name    string       `yaml:"name"`
	Cluster ClusterEntry `yaml:"cluster"`
}

// ClusterEntry datos del cluster
type ClusterEntry struct {
	Server                string `yaml:"server"`
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
	InsecureSkipTLSVerify bool   `yaml:"insecure-skip-tls-verify,omitempty"`
}

// KubeContext representa un contexto en kubeconfig
type KubeContext struct {
	Name    string       `yaml:"name"`
	Context ContextEntry `yaml:"context"`
}

// ContextEntry datos del contexto
type ContextEntry struct {
	Cluster   string `yaml:"cluster"`
	User      string `yaml:"user"`
	Namespace string `yaml:"namespace,omitempty"`
}

// KubeUser representa un usuario en kubeconfig
type KubeUser struct {
	Name string    `yaml:"name"`
	User UserEntry `yaml:"user"`
}

// UserEntry datos del usuario
type UserEntry struct {
	Token string `yaml:"token"`
}

// GenerateKubeconfig genera el archivo kubeconfig con el token actual
func (c *Config) GenerateKubeconfig(token string) error {
	// Usar valores por defecto si no están configurados
	clusterName := c.Cluster.Name
	if clusterName == "" {
		clusterName = "zcloud-homelab"
	}
	contextName := c.Cluster.Context
	if contextName == "" {
		contextName = "zcloud"
	}

	kubeconfig := KubeConfig{
		APIVersion:     "v1",
		Kind:           "Config",
		Preferences:    map[string]any{},
		CurrentContext: clusterName,
		Clusters: []KubeCluster{
			{
				Name: contextName,
				Cluster: ClusterEntry{
					Server: c.Server.URL + "/api/v1/k8s/proxy",
					// If the user explicitly configured the client in insecure mode (e.g. self-signed server cert),
					// mirror that behavior so `kubectl` works too.
					InsecureSkipTLSVerify: c.Server.Insecure,
				},
			},
		},
		Contexts: []KubeContext{
			{
				Name: clusterName,
				Context: ContextEntry{
					Cluster:   contextName,
					User:      "zcloud-user",
					Namespace: "default",
				},
			},
		},
		Users: []KubeUser{
			{
				Name: "zcloud-user",
				User: UserEntry{
					Token: token,
				},
			},
		},
	}

	// Serializar a YAML
	data, err := yaml.Marshal(&kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to marshal kubeconfig: %w", err)
	}

	// Asegurar que existe el directorio
	if err := os.MkdirAll(c.ConfigDir(), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Escribir archivo
	kubeconfigPath := filepath.Join(c.ConfigDir(), "kubeconfig")
	if err := os.WriteFile(kubeconfigPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write kubeconfig: %w", err)
	}

	return nil
}

// ClearKubeconfig limpia el token del kubeconfig
func (c *Config) ClearKubeconfig() error {
	return c.GenerateKubeconfig("")
}

// KubeconfigPath devuelve la ruta al kubeconfig
func (c *Config) KubeconfigPath() string {
	return filepath.Join(c.ConfigDir(), "kubeconfig")
}
