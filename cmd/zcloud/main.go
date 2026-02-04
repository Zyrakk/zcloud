package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// Set via -ldflags "-X main.Version=... -X main.BuildTime=..."
var (
	Version   = "dev"
	BuildTime = "unknown"
)

func shortPrefix(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "zcloud",
		Short: "ZCloud CLI - Remote k3s cluster management",
		Long: `ZCloud CLI lets you connect to and manage your k3s cluster securely
from anywhere.

Examples:
  zcloud init https://api.zyrak.cloud    # Initial setup
  zcloud login                           # Login
  zcloud status                          # Cluster/session status
  zcloud k get pods -A                   # Run kubectl via proxy
  zcloud apply ./my-app.yaml             # Apply manifests`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Load config (except for init/version).
			if cmd.Name() != "init" && cmd.Name() != "version" {
				var err error
				cfg, err = client.LoadConfig(configDir)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
					os.Exit(1)
				}
			}
		},
	}

	// Global flag
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "", "Config directory (default: ~/.zcloud)")

	// Comandos
	rootCmd.AddCommand(
		initCmd(),
		loginCmd(),
		logoutCmd(),
		totpCmd(),
		statusCmd(),
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
	var reset bool
	var yes bool

	cmd := &cobra.Command{
		Use:   "init [server_url]",
		Short: "Initialize client configuration",
		Long: `Initializes the zcloud client.
Generates device keys and registers the device with the server.

Example:
  zcloud init https://api.zyrak.cloud`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if complete && reset {
				fmt.Fprintln(os.Stderr, "Error: --complete and --reset cannot be used together")
				os.Exit(1)
			}

			if reset {
				dir := configDir
				if dir == "" {
					dir = client.DefaultConfigDir()
				}
				if !yes {
					fmt.Printf("This will delete %s\n", dir)
					fmt.Print("Type 'yes' to confirm: ")
					reader := bufio.NewReader(os.Stdin)
					line, _ := reader.ReadString('\n')
					line = strings.TrimSpace(line)
					if line != "yes" {
						fmt.Println("Cancelled.")
						return
					}
				}

				home, _ := os.UserHomeDir()
				if home != "" {
					cleanDir := filepath.Clean(dir)
					if cleanDir == home || cleanDir == filepath.Clean(home)+string(os.PathSeparator) {
						fmt.Fprintln(os.Stderr, "Error: refusing to delete home directory")
						os.Exit(1)
					}
				}

				if err := os.RemoveAll(dir); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to delete config: %v\n", err)
					os.Exit(1)
				}
				fmt.Println("✅ Configuration deleted")
			}

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
				// Complete initialization after approval.
				if err := auth.CompleteInit(); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if len(args) == 0 {
				fmt.Fprintln(os.Stderr, "Error: server URL is required")
				fmt.Fprintln(os.Stderr, "Usage: zcloud init https://api.zyrak.cloud")
				os.Exit(1)
			}

			if err := auth.Init(args[0]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().BoolVar(&complete, "complete", false, "Complete initialization after approval")
	cmd.Flags().BoolVar(&reset, "reset", false, "Delete local configuration and re-initialize (dangerous)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Do not prompt for confirmation (useful with --reset)")

	return cmd
}

// loginCmd logs into the server (optionally forcing renewal).
func loginCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login to the server",
		Long: `Authenticates with a TOTP code and generates a session token.

The token is valid for 12 hours. After running this command,
you can use 'kubectl' directly using the generated kubeconfig.

Example:
  zcloud login`,
		Run: func(cmd *cobra.Command, args []string) {
			// Ensure the device is configured.
			if !cfg.IsInitialized() {
				fmt.Fprintln(os.Stderr, "Error: device not configured")
				fmt.Fprintln(os.Stderr, "   Run: zcloud init <server_url>")
				os.Exit(1)
			}

			if !cfg.IsApproved() {
				fmt.Fprintln(os.Stderr, "Error: device not approved")
				fmt.Fprintln(os.Stderr, "   Run: zcloud init --complete")
				os.Exit(1)
			}

			// If there's already a valid session, keep it unless --force.
			if cfg.IsSessionValid() && !force {
				expires := cfg.SessionExpiresIn()
				fmt.Printf("✅ You already have an active session\n")
				fmt.Printf("   ☸ Cluster: %s\n", getClusterName(cfg))
				fmt.Printf("   ⏰ Expires in: %s\n", formatDuration(expires))
				// Ensure kubeconfig exists/has the current token.
				if err := cfg.GenerateKubeconfig(cfg.Session.Token); err == nil {
					fmt.Printf("💡 Kubeconfig: %s\n", cfg.KubeconfigPath())
				}
				fmt.Println()
				fmt.Println("💡 Use 'zcloud login --force' to renew")
				return
			}

			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// If --force and we already had a valid session, revoke it (best-effort) to avoid leaving stale tokens around.
			if force && cfg.IsSessionValid() {
				_ = auth.GetClient().Logout()
				cfg.ClearSession()
				_ = cfg.Save()
			}

			// Device info header
			fmt.Println()
			fmt.Println("🔐 ZCloud - Login")
			fmt.Printf("   Device: %s (%s)\n", cfg.Device.Name, shortPrefix(cfg.Device.ID, 8))
			fmt.Println()

			if err := auth.Login(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Generate kubeconfig with the new token
			if err := cfg.GenerateKubeconfig(cfg.Session.Token); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to generate kubeconfig: %v\n", err)
				os.Exit(1)
			}

			// Mark as trusted once TOTP has been set up successfully on this device.
			if !cfg.Device.Trusted {
				cfg.Device.Trusted = true
				_ = cfg.Save()
			}

			// Result
			fmt.Println()
			fmt.Println("✅ Session started")
			fmt.Printf("   ☸ Cluster: %s\n", getClusterName(cfg))
			fmt.Printf("   ⏰ Valid until: %s (%s)\n",
				cfg.Session.ExpiresAt.Format("15:04"),
				formatDuration(cfg.SessionExpiresIn()))
			fmt.Println()
			fmt.Printf("💡 Kubeconfig: %s\n", cfg.KubeconfigPath())
			fmt.Println("💡 You can now use 'kubectl' directly")
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Force a new session even if a valid one exists")
	return cmd
}

// logoutCmd logs out and cleans up kubeconfig.
func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Logout and clean kubeconfig",
		Run: func(cmd *cobra.Command, args []string) {
			hadSession := cfg.HasValidSession()

			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.Logout(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			// Limpiar kubeconfig (best-effort)
			_ = cfg.ClearKubeconfig()
			if hadSession {
				fmt.Println("👋 Logged out")
			} else {
				fmt.Println("No active session")
			}
			fmt.Println("   Kubeconfig cleaned")
		},
	}
}

// totpCmd configures TOTP for a user/persona.
func totpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "totp [enrollment_code]",
		Short: "Set up TOTP for your user/persona",
		Long: `Configures TOTP for a user/persona.
Run this after your device is approved, before your first login
(you only need to do this once per user).

Example:
  zcloud totp ABCD-EFGH-IJKL`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			code := ""
			if len(args) == 1 {
				code = args[0]
			}
			if err := auth.SetupTOTP(code); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
}

// statusCmd shows cluster/session status.
func statusCmd() *cobra.Command {
	var checkOnly bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show cluster/session status",
		Run: func(cmd *cobra.Command, args []string) {
			if checkOnly {
				// Quiet mode - only exit code
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

	cmd.Flags().BoolVar(&checkOnly, "check-only", false, "Only check session; no output (exit 0=valid, 1=invalid)")
	return cmd
}

// formatDuration formats a duration like "2h 10m" for display.
func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// getClusterName resolves the display name for the cluster.
func getClusterName(cfg *client.Config) string {
	if cfg.Cluster.Name != "" {
		return cfg.Cluster.Name
	}
	return "zcloud-homelab"
}

// kubectlCmd proxies kubectl calls through the server.
func kubectlCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "k [kubectl args...]",
		Short:              "Run kubectl commands against the remote cluster",
		Long:               `Transparent kubectl proxy. All arguments are passed through.`,
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

// applyCmd applies manifests remotely (kubectl apply -f).
func applyCmd() *cobra.Command {
	var namespace string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "apply [file.yaml]",
		Short: "Apply Kubernetes manifests",
		Long: `Apply one or more YAML files to the remote cluster.

Examples:
  zcloud apply deployment.yaml
  zcloud apply ./k8s/
  zcloud apply service.yaml -n my-namespace`,
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

			// Read manifests
			var manifests []string
			for _, path := range args {
				content, err := readManifest(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to read %s: %v\n", path, err)
					os.Exit(1)
				}
				manifests = append(manifests, content...)
			}

			if len(manifests) == 0 {
				fmt.Fprintln(os.Stderr, "No manifests found")
				os.Exit(1)
			}

			fmt.Printf("📤 Applying %d manifest(s)...\n", len(manifests))

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

			// Print results
			for _, r := range resp.Results {
				if r.Error != "" {
					fmt.Printf("Error: %s\n", r.Error)
				} else {
					fmt.Printf("✅ %s/%s %s\n", r.Kind, r.Name, r.Action)
				}
			}

			if !resp.Success {
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Target namespace")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Dry-run (do not apply changes)")

	return cmd
}

// execCmd - Ejecutar comandos remotos
func execCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "exec [command]",
		Short: "Execute a command on the server",
		Long: `Execute an allowed command on the remote server.

Allowed commands: kubectl, helm, k3s

Example:
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
		Short: "Administration commands",
	}

	// Subcomando devices
	devicesCmd := &cobra.Command{
		Use:   "devices",
		Short: "Manage devices",
	}

	// devices list
	devicesCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List registered devices",
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
				fmt.Println("No devices registered")
				return
			}

			fmt.Println()
			fmt.Printf("%-14s %-20s %-20s %-10s\n", "ID", "NAME", "LAST ACCESS", "STATUS")
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

				fmt.Printf("%-14s %-15s %-20s %-10s\n", shortPrefix(d.ID, 12), d.Name, lastAccess, status)
			}
			fmt.Println()
		},
	})

	// devices approve
	approveCmd := &cobra.Command{
		Use:   "approve [device_id]",
		Short: "Approve a device",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			userName, _ := cmd.Flags().GetString("user")

			auth, err := client.NewAuth(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := auth.EnsureSession(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			resp, err := auth.GetClient().ApproveDevice(args[0], userName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("✅ Device approved")
			if resp != nil && resp.UserName != "" {
				fmt.Printf("👤 User: %s\n", resp.UserName)
			}
			if resp != nil && resp.EnrollmentCode != "" {
				fmt.Println()
				fmt.Println("🔐 TOTP enrollment code (one-time):")
				fmt.Printf("   %s\n", resp.EnrollmentCode)
				if !resp.EnrollmentExpiresAt.IsZero() {
					fmt.Printf("   Expires: %s\n", resp.EnrollmentExpiresAt.Format("2006-01-02 15:04"))
				}
				fmt.Println()
				fmt.Println("The user must run:")
				fmt.Printf("   zcloud totp %s\n", resp.EnrollmentCode)
			}
		},
	}
	approveCmd.Flags().String("user", "", "User/persona name to assign this device to (per-user TOTP)")
	devicesCmd.AddCommand(approveCmd)

	// devices revoke
	devicesCmd.AddCommand(&cobra.Command{
		Use:   "revoke [device_id]",
		Short: "Revoke a device",
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

			fmt.Println("✅ Device revoked")
		},
	})

	cmd.AddCommand(devicesCmd)

	return cmd
}

// sshCmd - Conexión SSH interactiva
func sshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh",
		Short: "Open an interactive shell on the server",
		Long: `Starts an interactive shell session against the ZCloud server.

The connection uses WebSocket with JWT authentication and supports terminal resize.

Example:
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
		Short: "Port-forward to remote services",
		Long: `Creates a TCP tunnel from a local port to a remote service.

The host can be:
  - A k8s service: grafana.monitoring.svc
  - localhost for services on the server
  - Any host reachable from the server

Examples:
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

			// Parse host and ports
			targetHost := args[0]
			portParts := strings.Split(args[1], ":")
			if len(portParts) != 2 {
				fmt.Fprintln(os.Stderr, "Error: invalid port mapping, use localPort:remotePort")
				os.Exit(1)
			}

			localPort, err := strconv.Atoi(portParts[0])
			if err != nil || localPort <= 0 || localPort > 65535 {
				fmt.Fprintln(os.Stderr, "Error: invalid local port")
				os.Exit(1)
			}

			remotePort, err := strconv.Atoi(portParts[1])
			if err != nil || remotePort <= 0 || remotePort > 65535 {
				fmt.Fprintln(os.Stderr, "Error: invalid remote port")
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
		Use:   "cp [source] [dest]",
		Short: "Copy files between local and remote",
		Long: `Copy files between your machine and the server.

Use the 'remote:' prefix to indicate remote paths on the server.

Examples:
  zcloud cp file.txt remote:/path/to/dest/
  zcloud cp remote:/path/to/file.txt ./local/
  zcloud cp -r ./folder/ remote:/dest/`,
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

			// Validate that one side is remote and the other is local.
			if srcRemote == dstRemote {
				if srcRemote {
					fmt.Fprintln(os.Stderr, "Error: remote-to-remote copy is not supported")
				} else {
					fmt.Fprintln(os.Stderr, "Error: use your system 'cp' for local-to-local copies")
				}
				os.Exit(1)
			}

			filesClient := client.NewFilesClient(cfg)

			if srcRemote {
				// Download: remote -> local
				fmt.Printf("📥 Downloading %s -> %s\n", srcPath, dstPath)
				if err := filesClient.Download(srcPath, dstPath); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
				fmt.Println("✅ Download completed")
			} else {
				// Upload: local -> remote
				info, err := os.Stat(srcPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}

				if info.IsDir() {
					if !recursive {
						fmt.Fprintln(os.Stderr, "Error: use -r to copy directories")
						os.Exit(1)
					}
					fmt.Printf("📤 Uploading directory %s -> %s\n", srcPath, dstPath)
					results, err := filesClient.UploadDir(srcPath, dstPath)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error: %v\n", err)
						os.Exit(1)
					}
					fmt.Printf("✅ %d files uploaded\n", len(results))
				} else {
					fmt.Printf("📤 Uploading %s -> %s\n", srcPath, dstPath)
					result, err := filesClient.Upload(srcPath, dstPath)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error: %v\n", err)
						os.Exit(1)
					}
					fmt.Printf("✅ %s (%d bytes, SHA256: %s)\n", result.Path, result.Size, shortPrefix(result.Checksum, 12))
				}
			}
		},
	}

	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Copy directories recursively")

	return cmd
}

// versionCmd - Mostrar versión
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print zcloud version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("zcloud %s (%s)\n", Version, BuildTime)
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
