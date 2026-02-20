package main

import (
	"flag"
	"fmt"
	"gozuh/internal/service"
	"os"

	"golang.org/x/sys/windows/svc"
)
const AppVersion = "1.4.1.0"
func main() {
	isService, _ := svc.IsWindowsService()
	if isService {
		runService()
		return
	}
	opts := service.CLIOptions{}
	showVersion := flag.Bool("version", false, "Print Gozuh version")
	flag.BoolVar(&opts.ActionConfigure, "configure", false, "Mode: Setup config.json only (Encryption Enabled)")
	flag.BoolVar(&opts.ActionInstall, "install", false, "Mode: Install, Register & Harden Agent")
	flag.StringVar(&opts.InstallerName, "name", "", "[REQUIRED for Install] Filename of the MSI (e.g. wazuh-agent.msi)")
	flag.StringVar(&opts.InstallerSource, "installer", "", "[OPTIONAL] Local path OR HTTP URL to download MSI")
	flag.StringVar(&opts.MgrURL, "mgr-url", "", "[REQUIRED] Wazuh Manager URL (e.g. https://192.168.1.100)")
	flag.StringVar(&opts.MgrUser, "mgr-user", "", "[REQUIRED] API Username")
	flag.StringVar(&opts.MgrPass, "mgr-pass", "", "[REQUIRED] API Password")
	flag.StringVar(&opts.IdxURL, "idx-url", "", "[OPTIONAL] Indexer URL (If different from Manager)")
	flag.StringVar(&opts.IdxUser, "idx-user", "", "[OPTIONAL] Indexer User (If different from Manager)")
	flag.StringVar(&opts.IdxPass, "idx-pass", "", "[OPTIONAL] Indexer Pass (If different from Manager)")
	flag.StringVar(&opts.Group, "group", "", "[OPTIONAL] Agent Group (Default: 'default')")
	flag.BoolVar(&opts.EnableCIS, "enable-cis", false, "[OPTIONAL] Enable CIS Benchmarks (Default: Disabled)")
	flag.BoolVar(&opts.AllowVirtual, "allow-virtual", false, "Toggle: Enable Virtual NIC Support (for VMs)")
	flag.BoolVar(&opts.DenyVirtual, "deny-virtual", false, "Toggle: Disable Virtual NIC Support (Physical Only)")
	flag.BoolVar(&opts.EnableRemote, "enable-remote-command", false, "Set remote_commands=1 (Default: true if not specified)")
	flag.BoolVar(&opts.DisableRemote, "disable-remote-command", false, "Set remote_commands=0")
	flag.IntVar(&opts.Interval, "interval", 0, "")

	debug := flag.Bool("debug", false, "Run Diagnostics & Identity Check")
	purge := flag.Bool("purge", false, "Full Decommission (Remove from Server & Local)")
	destroy := flag.Bool("destroy", false, "Self-Destruct: Uninstall + Purge + Delete Gozuh folder")
	uninstall := flag.Bool("uninstall", false, "Local Uninstall Only")
	stop := flag.Bool("stop", false, "Stop Gozuh & Wazuh Services")
	restart := flag.Bool("restart", false, "Restart Gozuh & Wazuh Services")
	help := flag.Bool("help", false, "Show this help guide")
	alert := flag.Bool("alert", false, "Pop a test Security Alert Notification on active Desktop")
	alertWorker := flag.Bool("alert-worker", false, "")

	flag.Usage = func() {
		printBanner()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("Gozuh v%s\n", AppVersion)
		return
	}

	if *help {
		printBanner()
		return
	}
	if *debug {
		service.RunDebug()
		return
	}
	if *alertWorker {
		service.RunAlertWorker()
		return
	}
	if *alert {
		service.RunAlert()
		return
	}
	if *purge {
		service.RunPurge()
		return
	}
	if *destroy {
		service.RunDestroy()
		return
	}
	if *uninstall {
		service.RunUninstall()
		return
	}
	if *stop {
		service.RunServiceControl("stop")
		return
	}
	if *restart {
		service.RunServiceControl("restart")
		return
	}

	if opts.ActionConfigure {
		service.RunConfigure(opts)
		return
	}

	if opts.ActionInstall {
		if opts.InstallerName == "" {
			fmt.Println("\n[ERROR] Missing required flag: --name")
			fmt.Println("You MUST specify the MSI filename (e.g., --name wazuh-agent.msi)")
			fmt.Println("Run 'gozuh.exe --help' for examples.")
			os.Exit(1)
		}
		service.RunInstall(opts)
		return
	}
	printBanner()
}

func runService() {
	svc.Run("GOZUH", &service.GozuhService{})
}

func printBanner() {
	fmt.Printf(`
==============================================================================
   GOZUH - Wazuh Agent Companion (v%s)
==============================================================================

USAGE:
  gozuh.exe [ACTION] [FLAGS...]

------------------------------------------------------------------------------
 1. CONFIGURATION MODE (--configure)
    Creates an encrypted 'config.json'. Safe to run repeatedly (Idempotent).

    REQUIRED FLAGS:
      --mgr-url   : Wazuh Manager URL (e.g. https://192.168.0.10)
      --mgr-user  : API Username
      --mgr-pass  : API Password

    OPTIONAL FLAGS:
      --group     : Agent Group (Default: default)
      --idx-url   : Indexer URL (if different from Manager)
	  --interval  : Watchdog sync interval in seconds (Default: 60, Min: 10)
      --allow-virtual : Enable support for Virtual Machines (Hyper-V/VMware)
      --disable-remote-command : Block server from executing remote commands.
	  --enable-remote-command : Allow server to execute remote commands (Default).

------------------------------------------------------------------------------
 2. INSTALLATION MODE (--install)
    Downloads (if needed), Installs MSI, Registers Agent, and Hardens Config.

    REQUIRED FLAGS:
      --name      : The exact filename of the MSI (e.g. wazuh-agent-4.14.msi)
                    (This file must exist locally OR be downloadable)

    OPTIONAL FLAGS:
      --installer : Path to local file OR HTTP URL to download.
                    (If skipped, Gozuh looks for '--name' in current folder)
      --enable-cis: Skip disabling CIS Benchmark policies.

------------------------------------------------------------------------------
 3. UTILITY COMMANDS
    --version     : Show Gozuh version
    --debug       : Show Hardware Identity (UUID, Serial, MAC Hash) & API Status
    --alert       : Show Security Alert Notification Pop-up on active Desktop
    --stop        : Stop Gozuh & Wazuh services safely
    --restart     : Restart services (Triggers Watchdog)
    --uninstall   : Remove Service & Uninstall Agent (Keep Config)
    --purge       : Uninstall + Delete Agent from Wazuh Server (Clean Wipe)
    --destroy     : Uninstall + Purge + Delete Gozuh folder (Self-Destruct)

==============================================================================
 EXAMPLES (Copy & Paste):
==============================================================================

  [SCENARIO A] Configure First, Then Install (Recommended)
    1. Setup Config:
       gozuh.exe --configure --mgr-url https://10.0.0.5 --mgr-user admin --mgr-pass Secret123

    2. Run Install (Uses config above):
       gozuh.exe --install --name wazuh-agent-4.14.1.msi

  [SCENARIO B] One-Liner Download & Install
       gozuh.exe --install --group default --name wazuh-agent-4.14.1-1.msi --installer "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.1-1.msi" --mgr-url https://192.168.0.230:55000 --mgr-user wazuh-wui --mgr-pass "MyS3cr37P450r.*-" --idx-url https://192.168.0.230:9200 --idx-user admin --idx-pass "SecretPassword"

  [SCENARIO C] Enable Virtual Machine Support (Hyper-V / VirtualBox)
       gozuh.exe --configure --allow-virtual
       gozuh.exe --debug

==============================================================================`, AppVersion)
	fmt.Println()
}