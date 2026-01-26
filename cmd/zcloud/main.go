package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zyrak/zcloud/internal/client"
	"github.com/zyrak/zcloud/internal/shared/protocol"
)

var (
	configDir string
	cfg       *client.Config
	auth      *client.Auth
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "zcloud",
		Short: "ZCloud CLI - Gestiona tu cluster k3s de forma remota",
		Long: `ZCloud CLI permite conectarte y gestionar tu cluster k3s
desde cualquier lugar de forma segura.

Ejemplos:
  zcloud init https://api.zyrak.cloud    # Configuración inicial
  zcloud login                           # Iniciar sesión
  zcloud status                          # Ver estado del cluster
  zcloud k get pods -A                   # Ejecutar comandos kubectl
  zcloud apply ./mi-app.yaml             # Desplegar manifests`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Cargar configuración (excepto para init)
			if cmd.Name() != "init" && cmd.Name() != "version" {
				var err error
				cfg, err = client.LoadConfig(configDir)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error cargando configuración: %v\n", err)
					os.Exit(1)
				}
			}
		},
	}

	// Flag global
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "", "Directorio de configuración (default: ~/.zcloud)")

	// Comandos
	rootCmd.AddCommand(
		initCmd(),
		loginCmd(),
		logoutCmd(),
		totpCmd(),
		statusCmd(),
		startCmd(),
		stopCmd(),
		kubectlCmd(),
		applyCmd(),
		execCmd(),
		sshCmd(),
		portForwardCmd(),
		cpCmd(),
		adminCmd(),
		versionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// initCmd - Comando de inicialización
func initCmd() *cobra.Command {
	var complete bool

	cmd := &cobra.Command{
		Use:   "init [server_url]",
		Short: "Inicializa la configuración del cliente",
		Long: `Configura el cliente zcloud por primera vez.
Genera las claves del dispositivo y lo registra en el servidor.

Ejemplo:
  zcloud init https://api.zyrak.cloud`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			cfg, err = client.LoadConfig(configDir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			auth, err = client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if complete {
				// Completar inicialización después de aprobación
				if err := auth.CompleteInit(); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if len(args) == 0 {
				fmt.Fprintln(os.Stderr, "Error: se requiere la URL del servidor")
				fmt.Fprintln(os.Stderr, "Uso: zcloud init https://api.zyrak.cloud")
				os.Exit(1)
			}

			if err := auth.Init(args[0]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolVar(&complete, "complete", false, "Completar inicialización después de aprobación")

	return cmd
}

// loginCmd - Comando de login (alias de start)
func loginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Inicia sesión en el servidor (alias de 'start')",
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.Login(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Generar kubeconfig con el nuevo token
			if err := cfg.GenerateKubeconfig(cfg.Session.Token); err != nil {
				fmt.Fprintf(os.Stderr, "Error generando kubeconfig: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("☸ Kubeconfig: %s\n", cfg.KubeconfigPath())
		},
	}
}

// logoutCmd - Comando de logout
func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Cierra la sesión actual",
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.Logout(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
}

// totpCmd - Comando de configuración TOTP
func totpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "totp",
		Short: "Configura TOTP para el dispositivo",
		Long: `Configura la autenticación TOTP para un dispositivo aprobado.
Debe ejecutarse después de que el administrador apruebe el dispositivo
y antes del primer login.

Ejemplo:
  zcloud totp`,
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.SetupTOTP(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
}

// statusCmd - Comando de status
func statusCmd() *cobra.Command {
	var checkOnly bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Muestra el estado del cluster y la sesión",
		Run: func(cmd *cobra.Command, args []string) {
			if checkOnly {
				// Modo silencioso - solo exit code
				if cfg.IsSessionValid() {
					os.Exit(0)
				} else {
					os.Exit(1)
				}
			}

			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.Status(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check-only", false, "Solo verificar sesión, sin output (exit code 0=válida, 1=inválida)")
	return cmd
}

// startCmd - Comando de inicio de sesión diaria
func startCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Inicia sesión diaria con TOTP",
		Long: `Autentica con código TOTP y genera token de sesión.

El token es válido por 12 horas. Después de ejecutar este comando,
puedes usar 'kubectl' directamente con el kubeconfig generado.

Ejemplo:
  zcloud start`,
		Run: func(cmd *cobra.Command, args []string) {
			// Verificar que el dispositivo está configurado
			if !cfg.IsInitialized() {
				fmt.Fprintln(os.Stderr, "❌ Dispositivo no configurado")
				fmt.Fprintln(os.Stderr, "   Ejecuta: zcloud init <server_url>")
				os.Exit(1)
			}

			if !cfg.IsApproved() {
				fmt.Fprintln(os.Stderr, "❌ Dispositivo no aprobado")
				fmt.Fprintln(os.Stderr, "   Ejecuta: zcloud init --complete")
				os.Exit(1)
			}

			// Verificar si ya hay sesión válida
			if cfg.IsSessionValid() && !force {
				expires := cfg.SessionExpiresIn()
				fmt.Printf("✅ Ya tienes una sesión activa\n")
				fmt.Printf("   ☸ Cluster: %s\n", getClusterName(cfg))
				fmt.Printf("   ⏰ Expira en: %s\n", formatDuration(expires))
				fmt.Println()
				fmt.Println("💡 Usa 'zcloud start --force' para renovar")
				return
			}

			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Mostrar info del dispositivo
			fmt.Println()
			fmt.Println("🔐 ZCloud - Inicio de sesión")
			fmt.Printf("   Dispositivo: %s (%s)\n", cfg.Device.Name, cfg.Device.ID[:8])
			fmt.Println()

			// Hacer login (pide TOTP internamente)
			if err := auth.Login(); err != nil {
				fmt.Fprintf(os.Stderr, "\n❌ Error: %v\n", err)
				os.Exit(1)
			}

			// Generar kubeconfig con el nuevo token
			if err := cfg.GenerateKubeconfig(cfg.Session.Token); err != nil {
				fmt.Fprintf(os.Stderr, "Error generando kubeconfig: %v\n", err)
				os.Exit(1)
			}

			// Marcar como trusted si no lo estaba
			if !cfg.Device.Trusted {
				cfg.Device.Trusted = true
				_ = cfg.Save()
			}

			// Mostrar resultado
			fmt.Println()
			fmt.Println("✅ Sesión iniciada")
			fmt.Printf("   ☸ Cluster: %s\n", getClusterName(cfg))
			fmt.Printf("   ⏰ Válida hasta: %s (%s)\n",
				cfg.Session.ExpiresAt.Format("15:04"),
				formatDuration(cfg.SessionExpiresIn()))
			fmt.Println()
			fmt.Printf("💡 Kubeconfig: %s\n", cfg.KubeconfigPath())
			fmt.Println("💡 Ahora puedes usar 'kubectl' directamente")
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Forzar nueva sesión aunque ya exista una válida")
	return cmd
}

// stopCmd - Comando de cierre de sesión
func stopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Cierra la sesión actual y limpia kubeconfig",
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Logout en servidor
			_ = auth.Logout()

			// Limpiar kubeconfig
			_ = cfg.ClearKubeconfig()

			fmt.Println("👋 Sesión cerrada")
			fmt.Println("   Token invalidado en servidor")
			fmt.Println("   Kubeconfig limpiado")
		},
	}
}

// formatDuration formatea una duración legible
func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// getClusterName obtiene el nombre del cluster
func getClusterName(cfg *client.Config) string {
	if cfg.Cluster.Name != "" {
		return cfg.Cluster.Name
	}
	return "zcloud-homelab"
}

// kubectlCmd - Proxy a kubectl
func kubectlCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "k [kubectl args...]",
		Short:              "Ejecuta comandos kubectl en el cluster remoto",
		Long:               `Proxy transparente a kubectl. Todos los argumentos se pasan directamente.`,
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.EnsureSession(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			resp, err := auth.GetClient().KubectlProxy(args)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Stdout != "" {
				fmt.Print(resp.Stdout)
			}
			if resp.Stderr != "" {
				fmt.Fprint(os.Stderr, resp.Stderr)
			}

			os.Exit(resp.ExitCode)
		},
	}
}

// applyCmd - Aplicar manifests
func applyCmd() *cobra.Command {
	var namespace string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "apply [archivo.yaml]",
		Short: "Aplica manifests de Kubernetes",
		Long: `Aplica uno o más archivos YAML al cluster remoto.

Ejemplos:
  zcloud apply deployment.yaml
  zcloud apply ./k8s/
  zcloud apply -f service.yaml -n my-namespace`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.EnsureSession(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Leer archivos
			var manifests []string
			for _, path := range args {
				content, err := readManifest(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error leyendo %s: %v\n", path, err)
					os.Exit(1)
				}
				manifests = append(manifests, content...)
			}

			if len(manifests) == 0 {
				fmt.Fprintln(os.Stderr, "No se encontraron manifests")
				os.Exit(1)
			}

			fmt.Printf("📤 Aplicando %d manifest(s)...\n", len(manifests))

			req := &protocol.ApplyRequest{
				Manifests: manifests,
				Namespace: namespace,
				DryRun:    dryRun,
			}

			resp, err := auth.GetClient().Apply(req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Mostrar resultados
			for _, r := range resp.Results {
				if r.Error != "" {
					fmt.Printf("❌ Error: %s\n", r.Error)
				} else {
					fmt.Printf("✅ %s/%s %s\n", r.Kind, r.Name, r.Action)
				}
			}

			if !resp.Success {
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace de destino")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Simular sin aplicar cambios")

	return cmd
}

// execCmd - Ejecutar comandos remotos
func execCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exec [comando]",
		Short: "Ejecuta un comando en el servidor",
		Long: `Ejecuta un comando permitido en el servidor remoto.

Comandos permitidos: kubectl, helm, k3s

Ejemplo:
  zcloud exec kubectl get nodes`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.EnsureSession(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			req := &protocol.ExecRequest{
				Command: args[0],
				Args:    args[1:],
			}

			resp, err := auth.GetClient().Exec(req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if resp.Stdout != "" {
				fmt.Print(resp.Stdout)
			}
			if resp.Stderr != "" {
				fmt.Fprint(os.Stderr, resp.Stderr)
			}

			os.Exit(resp.ExitCode)
		},
	}
}

// adminCmd - Comandos de administración
func adminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Comandos de administración",
	}

	// Subcomando devices
	devicesCmd := &cobra.Command{
		Use:   "devices",
		Short: "Gestionar dispositivos",
	}

	// devices list
	devicesCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "Listar dispositivos registrados",
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.EnsureSession(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			devices, err := auth.GetClient().ListDevices()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if len(devices) == 0 {
				fmt.Println("No hay dispositivos registrados")
				return
			}

			fmt.Println()
			fmt.Printf("%-14s %-15s %-20s %-10s\n", "ID", "NOMBRE", "ÚLTIMO ACCESO", "ESTADO")
			fmt.Println(strings.Repeat("-", 65))

			for _, d := range devices {
				lastAccess := "-"
				if !d.LastAccess.IsZero() {
					lastAccess = d.LastAccess.Format("2006-01-02 15:04")
				}

				status := string(d.Status)
				switch d.Status {
				case protocol.DeviceStatusApproved:
					status = "✅ " + status
				case protocol.DeviceStatusPending:
					status = "⏳ " + status
				case protocol.DeviceStatusRevoked:
					status = "❌ " + status
				}

				fmt.Printf("%-14s %-15s %-20s %-10s\n", d.ID[:12], d.Name, lastAccess, status)
			}
			fmt.Println()
		},
	})

	// devices approve
	devicesCmd.AddCommand(&cobra.Command{
		Use:   "approve [device_id]",
		Short: "Aprobar un dispositivo",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.EnsureSession(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.GetClient().ApproveDevice(args[0]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("✅ Dispositivo aprobado")
		},
	})

	// devices revoke
	devicesCmd.AddCommand(&cobra.Command{
		Use:   "revoke [device_id]",
		Short: "Revocar un dispositivo",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.EnsureSession(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.GetClient().RevokeDevice(args[0]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("✅ Dispositivo revocado")
		},
	})

	cmd.AddCommand(devicesCmd)

	return cmd
}

// sshCmd - Conexión SSH interactiva
func sshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh",
		Short: "Abre una shell interactiva en el servidor",
		Long: `Inicia una sesión SSH interactiva con el servidor ZCloud.

La conexión se realiza a través de WebSocket con autenticación JWT.
Soporta redimensionamiento de terminal.

Ejemplo:
  zcloud ssh`,
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.EnsureSession(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			sshClient := client.SSHFromAuth(auth)
			if err := sshClient.Connect(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
}

// portForwardCmd - Port forwarding a servicios
func portForwardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "port-forward <host> <localPort>:<remotePort>",
		Short: "Forward de puertos a servicios remotos",
		Long: `Crea un túnel TCP desde un puerto local hacia un servicio remoto.

El host puede ser:
  - Un servicio k8s: grafana.monitoring.svc
  - localhost para servicios en el servidor
  - Cualquier host accesible desde el servidor

Ejemplos:
  zcloud port-forward grafana.monitoring.svc 3000:3000
  zcloud port-forward localhost 8080:80
  zcloud port-forward victoria.monitoring.svc 8428:8428`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.EnsureSession(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Parsear host y puertos
			targetHost := args[0]
			portParts := strings.Split(args[1], ":")
			if len(portParts) != 2 {
				fmt.Fprintln(os.Stderr, "Error: formato de puertos inválido, usa localPort:remotePort")
				os.Exit(1)
			}

			localPort, err := strconv.Atoi(portParts[0])
			if err != nil || localPort <= 0 || localPort > 65535 {
				fmt.Fprintln(os.Stderr, "Error: puerto local inválido")
				os.Exit(1)
			}

			remotePort, err := strconv.Atoi(portParts[1])
			if err != nil || remotePort <= 0 || remotePort > 65535 {
				fmt.Fprintln(os.Stderr, "Error: puerto remoto inválido")
				os.Exit(1)
			}

			pfClient := client.PortForwardFromAuth(auth)
			if err := pfClient.Forward(localPort, targetHost, remotePort); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
}

// cpCmd - Transferencia de archivos
func cpCmd() *cobra.Command {
	var recursive bool

	cmd := &cobra.Command{
		Use:   "cp [origen] [destino]",
		Short: "Copia archivos entre local y remoto",
		Long: `Copia archivos entre tu máquina y el servidor.

Usa el prefijo 'remote:' para indicar paths en el servidor.

Ejemplos:
  zcloud cp archivo.txt remote:/ruta/destino/
  zcloud cp remote:/ruta/archivo.txt ./local/
  zcloud cp -r ./carpeta/ remote:/destino/`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.EnsureSession(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			srcRemote, srcPath := client.ParseRemotePath(args[0])
			dstRemote, dstPath := client.ParseRemotePath(args[1])

			// Validar que origen y destino no sean ambos remotos o ambos locales
			if srcRemote == dstRemote {
				if srcRemote {
					fmt.Fprintln(os.Stderr, "Error: copia remoto a remoto no soportada")
				} else {
					fmt.Fprintln(os.Stderr, "Error: usa 'cp' del sistema para copias locales")
				}
				os.Exit(1)
			}

			filesClient := client.NewFilesClient(cfg)

			if srcRemote {
				// Download: remote -> local
				fmt.Printf("📥 Descargando %s -> %s\n", srcPath, dstPath)
				if err := filesClient.Download(srcPath, dstPath); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
				fmt.Println("✅ Descarga completada")
			} else {
				// Upload: local -> remote
				info, err := os.Stat(srcPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}

				if info.IsDir() {
					if !recursive {
						fmt.Fprintln(os.Stderr, "Error: usa -r para copiar directorios")
						os.Exit(1)
					}
					fmt.Printf("📤 Subiendo directorio %s -> %s\n", srcPath, dstPath)
					results, err := filesClient.UploadDir(srcPath, dstPath)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error: %v\n", err)
						os.Exit(1)
					}
					fmt.Printf("✅ %d archivos subidos\n", len(results))
				} else {
					fmt.Printf("📤 Subiendo %s -> %s\n", srcPath, dstPath)
					result, err := filesClient.Upload(srcPath, dstPath)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error: %v\n", err)
						os.Exit(1)
					}
					fmt.Printf("✅ %s (%d bytes, SHA256: %s)\n", result.Path, result.Size, result.Checksum[:12])
				}
			}
		},
	}

	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Copiar directorios recursivamente")

	return cmd
}

// versionCmd - Mostrar versión
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Muestra la versión de zcloud",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("zcloud version 1.0.0")
		},
	}
}

// Helpers

func readManifest(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		// Leer todos los archivos YAML del directorio
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}

		var manifests []string
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
				content, err := readManifest(path + "/" + name)
				if err != nil {
					return nil, err
				}
				manifests = append(manifests, content...)
			}
		}
		return manifests, nil
	}

	// Leer archivo
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Dividir por documentos YAML (---)
	docs := strings.Split(string(data), "\n---")
	var manifests []string
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc != "" {
			manifests = append(manifests, doc)
		}
	}

	return manifests, nil
}
