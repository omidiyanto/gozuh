package service

import (
	"encoding/base64"
	"fmt"
	"syscall"
	"gozuh/internal/config"
	"gozuh/internal/identity"
	"gozuh/internal/sys"
	"gozuh/internal/wazuh"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CLIOptions struct {
	ActionConfigure bool
	ActionInstall   bool

	InstallerSource string
	InstallerName   string

	MgrURL string
	MgrUser string
	MgrPass string

	IdxURL  string
	IdxUser string
	IdxPass string

	Group        string
	EnableCIS    bool
	AllowVirtual bool
	DenyVirtual  bool
	EnableRemote  bool
	DisableRemote bool
}

func getManagerHost(fullURL string) string {
	u, err := url.Parse(fullURL)
	if err != nil {
		return strings.Split(fullURL, ":")[0]
	}
	return u.Hostname()
}

func RunConfigure(opts CLIOptions) {
	DisableFileLogging()
	fmt.Println(">>> GOZUH CONFIGURATION SETUP <<<")

	conf, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("[WARN] Could not load existing config: %v\n", err)
	}

	if opts.MgrURL != "" { conf.ManagerURL = opts.MgrURL }
	if opts.MgrUser != "" { conf.ManagerUser = opts.MgrUser }
	if opts.MgrPass != "" { conf.ManagerPass = opts.MgrPass }
	if opts.IdxURL != "" { conf.IndexerURL = opts.IdxURL }
	if opts.IdxUser != "" { conf.IndexerUser = opts.IdxUser }
	if opts.IdxPass != "" { conf.IndexerPass = opts.IdxPass }
	if opts.Group != "" { conf.AgentGroup = opts.Group }
	if opts.InstallerName != "" { conf.InstallerName = opts.InstallerName }

	if opts.EnableCIS { conf.DisableCIS = false }

	if opts.AllowVirtual {
		conf.AllowVirtual = true
		fmt.Println("[CONFIG] Virtual NICs: ALLOWED")
	}
	if opts.DenyVirtual {
		conf.AllowVirtual = false
		fmt.Println("[CONFIG] Virtual NICs: DENIED (Physical Only)")
	}
	if opts.EnableRemote {
		conf.RemoteCommand = true
		fmt.Println("[CONFIG] Remote Commands: ENABLED")
	}
	if opts.DisableRemote {
		conf.RemoteCommand = false
		fmt.Println("[CONFIG] Remote Commands: DISABLED")
	}

	if conf.IndexerURL == "" { conf.IndexerURL = conf.ManagerURL }
	if conf.IndexerUser == "" { conf.IndexerUser = conf.ManagerUser }
	if conf.IndexerPass == "" { conf.IndexerPass = conf.ManagerPass }
	if conf.AgentGroup == "" { conf.AgentGroup = "default" }

	if conf.ManagerURL == "" || conf.ManagerUser == "" || conf.ManagerPass == "" {
		log.Fatal("[ERR] --mgr-url, --mgr-user, and --mgr-pass are required.")
	}

	if opts.Group != "" && conf.ManagerURL != "" {
		fmt.Println("[INFO] Attempting to push group update to Server...")
		api := wazuh.NewClient(conf.ManagerURL, conf.IndexerURL, conf.ManagerUser, conf.ManagerPass, conf.IndexerUser, conf.IndexerPass)
		hw, _ := identity.GetIdentity(conf.AllowVirtual)

		suffix := hw.Hash
		if len(hw.Hash) > 10 { suffix = hw.Hash[len(hw.Hash)-10:] }

		candidates, err := api.GetAgentCandidates(suffix)
		if err == nil {
			found := false
			for _, c := range candidates {
				match := false
				labels, err := api.GetAgentLabels(c.ID)
				if err == nil && strings.EqualFold(labels["hardware_hash"], hw.Hash) {
					match = true
				} else {
					verified, _ := api.VerifyHashInIndexer(c.ID, hw.Hash)
					if verified { match = true }
				}

				if match {
					fmt.Printf("   -> Found Agent ID: %s. Updating group to '%s'...\n", c.ID, opts.Group)
					err := api.AssignGroups(c.ID, opts.Group)
					if err != nil {
						fmt.Printf("   [WARN] Failed to update server: %v. Saved locally, Watchdog will retry later.\n", err)
					} else {
						fmt.Println("   [SUCCESS] Server updated.")
						found = true
					}
					break
				}
			}
			if !found {
				fmt.Println("   [INFO] Agent not found on server yet. Config saved for future registration.")
			}
		} else {
			fmt.Printf("   [WARN] Could not connect to API: %v. Saving locally only.\n", err)
		}
	}

	if err := config.SaveConfig(conf); err != nil {
		log.Fatalf("[ERR] Failed to save config: %v", err)
	}

	if opts.Group != "" {
		wazuh.UpdateAgentGroup(opts.Group)
	}
	wazuh.SetRemoteCommands(conf.RemoteCommand)

	fmt.Println("[OK] Configuration saved successfully.")
}

func RunInstall(opts CLIOptions) {
	DisableFileLogging()
	fmt.Println(">>> STARTING INSTALLATION SEQUENCE <<<")

	conf, _ := config.LoadConfig()

	if opts.MgrURL != "" { conf.ManagerURL = opts.MgrURL }
	if opts.MgrUser != "" { conf.ManagerUser = opts.MgrUser }
	if opts.MgrPass != "" { conf.ManagerPass = opts.MgrPass }
	if opts.IdxURL != "" { conf.IndexerURL = opts.IdxURL }
	if opts.IdxUser != "" { conf.IndexerUser = opts.IdxUser }
	if opts.IdxPass != "" { conf.IndexerPass = opts.IdxPass }
	if opts.Group != "" { conf.AgentGroup = opts.Group }
	if opts.InstallerName != "" { conf.InstallerName = opts.InstallerName }
	if opts.EnableCIS { conf.DisableCIS = false }
	if opts.AllowVirtual { conf.AllowVirtual = true }
	if opts.DenyVirtual { conf.AllowVirtual = false }
	if opts.EnableRemote { conf.RemoteCommand = true }
	if opts.DisableRemote { conf.RemoteCommand = false }

	if conf.IndexerURL == "" { conf.IndexerURL = conf.ManagerURL }
	if conf.IndexerUser == "" { conf.IndexerUser = conf.ManagerUser }
	if conf.IndexerPass == "" { conf.IndexerPass = conf.ManagerPass }
	if conf.AgentGroup == "" { conf.AgentGroup = "default" }

	if conf.ManagerURL == "" || conf.ManagerUser == "" || conf.ManagerPass == "" {
		log.Fatal("[FATAL] Missing Credentials. Use --configure or provide arguments.")
	}
	if conf.InstallerName == "" {
		log.Fatal("[FATAL] --name (installer filename) is REQUIRED.")
	}

	config.SaveConfig(conf)

	targetMsiPath := filepath.Join(config.AppDir, conf.InstallerName)
	fileExist := false
	if _, err := os.Stat(targetMsiPath); err == nil {
		fileExist = true
	}

	if fileExist {
		fmt.Printf("[INFO] Installer found locally at %s. Skipping download.\n", targetMsiPath)
	} else {
		if opts.InstallerSource != "" && strings.HasPrefix(opts.InstallerSource, "http") {
			fmt.Printf("[DOWNLOAD] Fetching from %s...\n", opts.InstallerSource)
			fmt.Printf("           Destination: %s\n", targetMsiPath)
			if err := downloadFile(opts.InstallerSource, targetMsiPath); err != nil {
				log.Fatalf("[FATAL] Download failed: %v", err)
			}
			fmt.Println("[DOWNLOAD] Success.")
		} else if opts.InstallerSource != "" {
			if _, err := os.Stat(opts.InstallerSource); err == nil {
				targetMsiPath = opts.InstallerSource
			} else {
				log.Fatalf("[FATAL] Source file '%s' not found.", opts.InstallerSource)
			}
		} else {
			log.Fatalf("[FATAL] Installer '%s' missing and no download source provided.", targetMsiPath)
		}
	}

	if _, err := os.Stat(targetMsiPath); os.IsNotExist(err) {
		log.Fatalf("[FATAL] Final check failed. Installer file not found at %s", targetMsiPath)
	}

	runBootstrap(conf, targetMsiPath)
}

func runBootstrap(conf *config.Config, installerPath string) {
	hw, _ := identity.GetIdentity(conf.AllowVirtual)

	if sys.GetServiceStatus(config.GozuhService) == "RUNNING" && sys.GetServiceStatus(config.WazuhService) == "RUNNING" {
		state, _ := config.LoadState()
		lbl, _ := wazuh.GetHardwareLabel()
		if state != nil && state.HardwareHash == hw.Hash && lbl == hw.Hash {
			fmt.Println("[SKIP] System is healthy and matches configuration.")
			return
		}
		fmt.Println("[INFO] State mismatch detected. Healing...")
	}

	api := wazuh.NewClient(conf.ManagerURL, conf.IndexerURL, conf.ManagerUser, conf.ManagerPass, conf.IndexerUser, conf.IndexerPass)
	suffix := hw.Hash
	if len(hw.Hash) > 10 { suffix = hw.Hash[len(hw.Hash)-10:] }
	rawHost, _ := os.Hostname()
	targetName := fmt.Sprintf("%s-%s", strings.ToLower(rawHost), suffix)

	var recoveryKey, recoveryID string

	fmt.Println("[STEP 1] Checking identity on server...")
	candidates, _ := api.GetAgentCandidates(suffix)

	for _, c := range candidates {
		match := false
		labels, err := api.GetAgentLabels(c.ID)

		if err == nil && strings.EqualFold(labels["hardware_hash"], hw.Hash) {
			match = true
		} else {
			verified, _ := api.VerifyHashInIndexer(c.ID, hw.Hash)
			if verified { match = true }
		}

		if match {
			fmt.Printf("   -> Found existing Agent ID: %s (Name: %s)\n", c.ID, c.Name)

			key, err := api.GetAgentKey(c.ID)
			if err == nil {
				recoveryKey, recoveryID = key, c.ID
			} else {
				fmt.Printf("      [ERR] Failed to get key for ID %s. Agent might be broken.\n", c.ID)
				continue
			}

			serverGroupsMap := make(map[string]bool)
			for _, g := range c.Group { serverGroupsMap[strings.ToLower(g)] = true }

			targetGroupsList := strings.Split(conf.AgentGroup, ",")
			needsUpdate := false

			for _, reqG := range targetGroupsList {
				reqG = strings.TrimSpace(reqG)
				if reqG == "" { continue }
				if !serverGroupsMap[strings.ToLower(reqG)] {
					needsUpdate = true
					break
				}
			}
			
			if needsUpdate {
				fmt.Printf("   -> Group Mismatch via CLI. Updating Server ID %s to group '%s'...\n", c.ID, conf.AgentGroup)
				if err := api.AssignGroups(c.ID, conf.AgentGroup); err != nil {
					fmt.Printf("      [WARN] Failed to update group on server: %v. Proceeding with local config injection.\n", err)
				} else {
					fmt.Println("      [OK] Server Group Updated.")
				}
			}
			break 
		}
	}

	fmt.Println("[STEP 2] Checking Wazuh Agent MSI...")
	mgrIP := getManagerHost(conf.ManagerURL)

	if sys.GetServiceStatus(config.WazuhService) == "NOT_INSTALLED" {
		fmt.Println("   -> Installing MSI...")
		if err := sys.InstallWazuhMSI(installerPath, mgrIP, targetName, conf.AgentGroup); err != nil {
			log.Fatalf("[FATAL] MSI Install: %v", err)
		}
	} else {
		fmt.Println("   -> MSI already installed.")
	}
	sys.StopService(config.WazuhService)

	fmt.Println("[STEP 3] Configuring...")
	if conf.DisableCIS {
		wazuh.DisableCISBenchmarks()
	} else {
		fmt.Println("   -> CIS Benchmarks ENABLED (Skipped disable).")
	}

	if err := wazuh.WipeLocalSyscheck(); err != nil {
		fmt.Printf("   [WARN] Failed to apply Syscheck optimization: %v\n", err)
	}
	
	wazuh.EnsureHardwareLabel(hw.Hash)
	wazuh.ApplyHardening()
	wazuh.UpdateAgentName(targetName)
	wazuh.UpdateAgentGroup(conf.AgentGroup)
	wazuh.SetRemoteCommands(conf.RemoteCommand)
	fmt.Println("[STEP 4] Managing Keys...")
	if recoveryKey != "" {
		fmt.Printf("   -> Restoring identity from server (ID: %s).\n", recoveryID)
		raw, _ := base64.StdEncoding.DecodeString(recoveryKey)
		os.WriteFile(config.WazuhClientKey, raw, 0644)
	} else {
		fmt.Println("   -> Clean install (New Identity).")
		os.Remove(config.WazuhClientKey)
	}

	fmt.Println("[STEP 5] Finalizing Services...")
	sys.StartService(config.WazuhService)

	if sys.GetServiceStatus(config.GozuhService) == "NOT_INSTALLED" {
		sys.InstallGozuhService()
		sys.StartGozuhService()
	} else {
		fmt.Println("   -> Restarting Gozuh Service...")
		sys.RestartGozuhService()
	}

	config.SaveState(&config.State{HardwareHash: hw.Hash, Hostname: targetName})
	fmt.Println(">>> DONE <<<")
}

func downloadFile(url string, dest string) error {
	out, err := os.Create(dest)
	if err != nil { return err }
	defer out.Close()

	client := http.Client{Timeout: 300 * time.Second}
	resp, err := client.Get(url)
	if err != nil { return err }
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	return err
}

func RunServiceControl(action string) {
	DisableFileLogging()
	if action == "stop" {
		fmt.Println("Stopping Gozuh & Wazuh...")
		sys.StopService(config.GozuhService)
		sys.StopService(config.WazuhService)
	} else if action == "restart" {
		fmt.Println("Restarting Gozuh & Wazuh...")
		sys.RestartGozuhService()
		sys.RestartWazuhAgent()
	}
}

func RunDebug() {
	DisableFileLogging()
	fmt.Println("\n========================================")
	fmt.Println("   GOZUH SYSTEM DEBUG INFORMATION")
	fmt.Println("========================================")

	conf, _ := config.LoadConfig()
	info, err := identity.GetIdentity(conf.AllowVirtual)

	if err != nil {
		fmt.Printf("[!] Error Scan Hardware: %v\n", err)
		return
	}

	suffix := "0000000000"
	if len(info.Hash) > 10 { suffix = info.Hash[len(info.Hash)-10:] }
	rawHost, _ := os.Hostname()
	targetName := fmt.Sprintf("%s-%s", strings.ToLower(rawHost), suffix)

	fmt.Println("[HARDWARE IDENTITY]")
	fmt.Printf(" UUID      : %s\n", info.UUID)
	fmt.Printf(" SERIAL    : %s\n", info.Serial)
	fmt.Printf(" MAC LIST  : %v [Count: %d]\n", info.MACList, len(info.MACList))
	fmt.Printf(" MAC HASH  : %s\n", info.MACHash)
	fmt.Printf(" FULL HASH : %s\n", info.Hash)
	fmt.Printf(" SUFFIX    : %s\n", suffix)
	fmt.Printf(" NAME REQ  : %s\n", targetName)
	if conf.AllowVirtual {
		fmt.Println(" [WARN] Virtual Interfaces Allowed (Testing Mode)")
	}

	localWazuhStatus := sys.GetServiceStatus("WazuhSvc")
	gozuhStatus := sys.GetServiceStatus("GOZUH")
	fmt.Println("\n[LOCAL STATUS]")
	fmt.Printf(" Wazuh Agent (WazuhSvc) : %s\n", localWazuhStatus)
	fmt.Printf(" Gozuh Service          : %s\n", gozuhStatus)

	fmt.Println("\n[SERVER DIAGNOSTICS]")
	api := wazuh.NewClient(conf.ManagerURL, conf.IndexerURL, conf.ManagerUser, conf.ManagerPass, conf.IndexerUser, conf.IndexerPass)

	if err := api.Authenticate(); err != nil {
		fmt.Printf(" [!] Connection Failed: %v\n", err)
		return
	}
	fmt.Println(" [OK] API Connection Successful.")

	fmt.Printf("\n[SMART CANDIDATE SEARCH (Suffix: %s)]\n", suffix)
	candidates, _ := api.GetAgentCandidates(suffix)
	fmt.Printf(" -> FOUND %d CANDIDATE(S)\n", len(candidates))

	for _, c := range candidates {
		fmt.Printf("    Checking Candidate: %s (ID: %s)... ", c.Name, c.ID)
		labels, err := api.GetAgentLabels(c.ID)
		if err == nil && strings.EqualFold(labels["hardware_hash"], info.Hash) {
			fmt.Println("[MATCH CONFIRMED] (Source: Config API)")
		} else {
			verified, _ := api.VerifyHashInIndexer(c.ID, info.Hash)
			if verified {
				fmt.Println("[MATCH CONFIRMED] (Source: Indexer Logs)")
			} else {
				fmt.Println("[MISMATCH]")
			}
		}
	}
	fmt.Println("========================================\n")
}

func RunPurge() {
	DisableFileLogging()
	fmt.Println(">>> STARTING ASSET DECOMMISSION (PURGE) <<<")
	conf, _ := config.LoadConfig()
	api := wazuh.NewClient(conf.ManagerURL, conf.IndexerURL, conf.ManagerUser, conf.ManagerPass, conf.IndexerUser, conf.IndexerPass)
	hw, _ := identity.GetIdentity(conf.AllowVirtual)
	suffix := hw.Hash
	if len(hw.Hash) > 10 { suffix = hw.Hash[len(hw.Hash)-10:] }
	candidates, _ := api.GetAgentCandidates(suffix)
	for _, c := range candidates {
		api.DeleteAgent(c.ID)
		fmt.Printf("   [DELETE] Removed %s (%s)\n", c.Name, c.ID)
	}
	RunUninstall()
	fmt.Println(">>> PURGE COMPLETE <<<")
}

func RunUninstall() {
	DisableFileLogging()
	fmt.Println(">>> UNINSTALLING... <<<")

	conf, _ := config.LoadConfig()
	msiName := "wazuh-agent-4.14.1-1.msi"
	if conf.InstallerName != "" {
		msiName = conf.InstallerName
	}

	sys.RemoveGozuhService()

	msiPath := filepath.Join(config.AppDir, msiName)
	fmt.Printf("[INFO] Attempting uninstall using %s\n", msiPath)
	cmd := exec.Command("msiexec", "/x", msiPath, "/qn")
	if err := cmd.Run(); err != nil {
		fmt.Printf("[WARN] Uninstall failed using file path: %v. Try manual removal.\n", err)
	}

	os.Remove(config.StateFile)
	fmt.Println(">>> UNINSTALL COMPLETE <<<")
}

func RunAlert() {
	DisableFileLogging()

	if sys.CheckAlertMutex() {
		fmt.Println("[SKIP] Alert is already active on the desktop.")
		return
	}

	fmt.Println("[ALERT] Spawning security notification in background...")

	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("[ERR] Failed to get executable path: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command(exe, "--alert-worker")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	
	if err := cmd.Start(); err != nil {
		fmt.Printf("[ERR] Failed to spawn background alert: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[OK] Background alert triggered successfully.")
}

func RunAlertWorker() {
	sys.ShowAlertWorker("Gozuh - Security Alert", "This Endpoint Require to be Checked, please contact IT Security Team")
}