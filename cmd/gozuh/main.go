package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"gozuh/internal/config"
	"gozuh/internal/identity"
	"gozuh/internal/service"
	"gozuh/internal/sys"
	"gozuh/internal/wazuh"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func main() {
	isService, _ := svc.IsWindowsService()
	if isService {
		runService()
		return
	}

	install := flag.Bool("install", false, "Smart Installation (Recovery/Fresh)")
	uninstall := flag.Bool("uninstall", false, "Local Uninstall (Keep Data on Server)")
	purge := flag.Bool("purge", false, "Full Decommission (Local Uninstall + Server Delete)")
	debug := flag.Bool("debug", false, "Debug Info & Pre-flight Check")
	flag.Parse()

	if *debug {
		runAdHocDebug()
		return
	}
	if *install {
		unifiedInstall()
		return
	}
	if *uninstall {
		unifiedUninstall()
		return
	}
	if *purge {
		unifiedPurge()
		return
	}

	fmt.Println("GOZUH Unified Agent Wrapper")
	fmt.Println("Usage:")
	flag.PrintDefaults()
}

func unifiedPurge() {
	fmt.Println(">>> STARTING ASSET DECOMMISSION (PURGE) <<<")
	fmt.Println("[WARN] This will remove the agent from this device AND the Wazuh Manager.")
	fmt.Println("[WARN] Recovery will NOT be possible after this.")

	fmt.Println("[STEP 1/2] Searching Agent on Server...")

	conf, _ := config.LoadConfig()
	api := wazuh.NewClient(conf.WazuhURL, conf.IndexerURL, conf.APIUser, conf.APIPass, conf.IndexerUser, conf.IndexerPass)

	hw, err := identity.GetIdentity()
	if err != nil {
		fmt.Printf("[SKIP] Could not determine hardware identity: %v\n", err)
	} else {
		suffix := "0000000000"
		if len(hw.Hash) > 10 {
			suffix = hw.Hash[len(hw.Hash)-10:]
		}

		fmt.Printf("   Target Identity: ...%s\n", suffix)

		candidates, err := api.GetAgentCandidates(suffix)
		if err != nil {
			fmt.Printf("   [ERR] API Search failed: %v\n", err)
		} else {
			deletedCount := 0
			for _, c := range candidates {
				isMatch := false

				labels, err := api.GetAgentLabels(c.ID)
				if err == nil {
					if strings.EqualFold(labels["hardware_hash"], hw.Hash) {
						isMatch = true
					}
				} else {
					fmt.Printf("   -> Verify ownership for ID %s (Disconnected)... ", c.ID)
					verified, _ := api.VerifyHashInIndexer(c.ID, hw.Hash)
					if verified {
						isMatch = true
						fmt.Println("MATCH (Logs found).")
					} else {
						fmt.Println("NO MATCH.")
					}
				}

				if isMatch {
					fmt.Printf("   [DELETE] Deleting Agent '%s' (ID: %s) from Manager...\n", c.Name, c.ID)
					resp, err := api.DeleteAgent(c.ID)
					if err == nil {
						fmt.Printf("   -> Success: %s\n", resp)
						deletedCount++
					} else {
						// FIX: Print 'resp' (Body) to debug error details
						fmt.Printf("   -> Failed: %v. Response: %s\n", err, resp)
					}
				}
			}

			if deletedCount == 0 {
				fmt.Println("   -> No matching agent found on server (Safe to proceed).")
			}
		}
	}

	fmt.Println("\n[STEP 2/2] Performing Local Cleanup...")
	unifiedUninstall()

	fmt.Println("\n>>> PURGE COMPLETE (ASSET DECOMMISSIONED) <<<")
}

func runAdHocDebug() {
	fmt.Println("\n========================================")
	fmt.Println("   GOZUH SYSTEM DEBUG INFORMATION")
	fmt.Println("========================================")

	info, err := identity.GetIdentity()
	if err != nil {
		fmt.Printf("[!] Error Scan Hardware: %v\n", err)
		return
	}

	suffix := "0000000000"
	if len(info.Hash) > 10 {
		suffix = info.Hash[len(info.Hash)-10:]
	}

	rawHost, _ := os.Hostname()
	targetName := fmt.Sprintf("%s-%s", strings.ToLower(rawHost), suffix)

	fmt.Println("[HARDWARE IDENTITY]")
	fmt.Printf(" UUID      : %s\n", info.UUID)
	fmt.Printf(" FULL HASH : %s\n", info.Hash)
	fmt.Printf(" SUFFIX    : %s\n", suffix)
	fmt.Printf(" NAME REQ  : %s\n", targetName)

	localWazuhStatus := sys.GetServiceStatus("WazuhSvc")
	fmt.Println("\n[LOCAL STATUS]")
	fmt.Printf(" Wazuh Agent (WazuhSvc) : %s\n", localWazuhStatus)

	fmt.Println("\n[SMART CANDIDATE SEARCH]")
	conf, _ := config.LoadConfig()
	api := wazuh.NewClient(conf.WazuhURL, conf.IndexerURL, conf.APIUser, conf.APIPass, conf.IndexerUser, conf.IndexerPass)

	if err := api.Authenticate(); err != nil {
		fmt.Printf(" [!] Connection Failed: %v\n", err)
	} else {
		candidates, err := api.GetAgentCandidates(suffix)
		if err != nil {
			fmt.Printf(" [!] Search Error: %v\n", err)
		} else {
			fmt.Printf(" -> FOUND %d CANDIDATE(S) with suffix '%s'\n", len(candidates), suffix)

			matchFound := false
			for _, c := range candidates {
				fmt.Printf("    Checking Candidate: %s (ID: %s)... ", c.Name, c.ID)

				labels, err := api.GetAgentLabels(c.ID)
				remoteHash := ""
				if err == nil {
					remoteHash = labels["hardware_hash"]
				}

				isMatch := false

				if strings.EqualFold(remoteHash, info.Hash) {
					fmt.Println("[MATCH CONFIRMED] (Source: Config API)")
					isMatch = true
				} else {
					fmt.Print("[DISCONNECTED] -> Checking Indexer History... ")
					verified, idxErr := api.VerifyHashInIndexer(c.ID, info.Hash)
					if idxErr != nil {
						fmt.Printf("[ERROR] %v\n", idxErr)
					} else if verified {
						fmt.Println("[MATCH CONFIRMED] (Source: Indexer Logs)")
						isMatch = true
					} else {
						fmt.Println("[MISMATCH] No matching logs found.")
					}
				}

				if isMatch {
					matchFound = true
					if localWazuhStatus == "NOT_INSTALLED" {
						fmt.Println("       >>> DECISION: [RECOVERY MODE] (Restore Key)")
					} else {
						fmt.Println("       >>> DECISION: [HEALTHY] (Already Running)")
					}
				}
			}

			if !matchFound {
				fmt.Println(" -> RESULT: No valid owner found. [FRESH INSTALL]")
			}
		}
	}
	fmt.Println("========================================\n")
}

func unifiedInstall() {
	fmt.Println(">>> STARTING SMART INSTALLATION (SUFFIX STRATEGY) <<<")

	hw, err := identity.GetIdentity()
	if err != nil {
		log.Fatalf("[FATAL] Hardware Error: %v", err)
	}

	// --- IDEMPOTENCY CHECK (Supaya aman di-run berkali-kali via Ansible/PDQ) ---
	// Cek 1: Apakah Service GOZUH sudah berjalan?
	gozuhStatus := sys.GetServiceStatus("GOZUH")
	wazuhStatus := sys.GetServiceStatus("WazuhSvc")

	// Cek 2: Apakah State Lokal konsisten dengan Hardware saat ini?
	state, _ := config.LoadState()
	isStateValid := (state != nil && state.HardwareHash == hw.Hash)

	// Cek 3: Apakah Key File ada?
	keyExists := false
	if _, err := os.Stat("C:\\Program Files (x86)\\ossec-agent\\client.keys"); err == nil {
		keyExists = true
	}

	if gozuhStatus == "RUNNING" && wazuhStatus == "RUNNING" && isStateValid && keyExists {
		fmt.Println("[SKIP] System is already HEALTHY and INSTALLED.")
		fmt.Printf("       - Hardware Identity : MATCH (%s)\n", hw.Hash[:10])
		fmt.Println("       - Services          : RUNNING")
		fmt.Println("       - Action            : NONE (Idempotent Exit)")
		return // KELUAR DISINI (Exit Code 0)
	}
	// --------------------------------------------------------------------------

	conf, _ := config.LoadConfig()
	api := wazuh.NewClient(conf.WazuhURL, conf.IndexerURL, conf.APIUser, conf.APIPass, conf.IndexerUser, conf.IndexerPass)
	managerIP := parseIPFromURL(conf.WazuhURL)

	suffix := "0000000000"
	if len(hw.Hash) > 10 {
		suffix = hw.Hash[len(hw.Hash)-10:]
	}

	rawHost, _ := os.Hostname()
	targetName := fmt.Sprintf("%s-%s", strings.ToLower(rawHost), suffix)

	fmt.Printf("[INFO] Identity: %s\n", targetName)

	var recoveryKeyB64 string
	var recoveryID string
	var recoveryName string

	fmt.Println("[STEP 2/6] Searching for Existing Owner...")
	candidates, _ := api.GetAgentCandidates(suffix)

	for _, c := range candidates {
		isMatch := false

		labels, err := api.GetAgentLabels(c.ID)
		if err == nil {
			if strings.EqualFold(labels["hardware_hash"], hw.Hash) {
				isMatch = true
			}
		} else {
			fmt.Printf("   -> Agent %s disconnected. Querying Indexer for evidence...\n", c.ID)
			verified, _ := api.VerifyHashInIndexer(c.ID, hw.Hash)
			if verified {
				isMatch = true
			}
		}

		if isMatch {
			fmt.Printf("   -> FOUND MATCH: Agent '%s' (ID: %s) is the owner.\n", c.Name, c.ID)

			if c.Name != targetName {
				fmt.Printf("   -> NAME MISMATCH (%s != %s). Migration Mode.\n", c.Name, targetName)
				fmt.Println("   -> Cleaning old record to allow rename...")
				api.DeleteAgent(c.ID)
			} else {
				fmt.Println("   -> PERFECT MATCH. Recovery Mode.")
				key, err := api.GetAgentKey(c.ID)
				if err == nil {
					recoveryKeyB64 = key
					recoveryID = c.ID
					recoveryName = c.Name
					fmt.Println("   -> Key fetched successfully.")
				} else {
					fmt.Printf("   -> [WARN] Key fetch failed: %v\n", err)
				}
			}
			break
		}
	}

	if recoveryID == "" {
		fmt.Println("   -> No valid owner found (Strict Check). Proceeding with FRESH INSTALL.")
	}

	// 3. INSTALL MSI
	if err := sys.InstallWazuhMSI(managerIP, targetName); err != nil {
		log.Fatalf("[FATAL] MSI Install Failed: %v", err)
	}

	// 4. STOP & CONFIGURE
	time.Sleep(5 * time.Second)
	s, err := sys.ConnectService("WazuhSvc")
	if err == nil {
		s.Control(svc.Stop)
		time.Sleep(3 * time.Second)
		s.Close()
	}

	wazuh.DisableCISBenchmarks()
	wazuh.EnsureHardwareLabel(hw.Hash)
	wazuh.ApplyHardening()
	wazuh.UpdateAgentName(targetName)

	// 5. RESTORE KEY
	if recoveryKeyB64 != "" {
		fmt.Printf("[RESTORE] Restoring session key for agent '%s' (ID: %s)...\n", recoveryName, recoveryID)

		keyPath := "C:\\Program Files (x86)\\ossec-agent\\client.keys"

		rawKeyBytes, err := base64.StdEncoding.DecodeString(recoveryKeyB64)
		if err != nil {
			fmt.Printf("   [ERR] Failed to decode base64 key: %v\n", err)
		} else {
			if err := os.WriteFile(keyPath, rawKeyBytes, 0644); err != nil {
				fmt.Printf("   [ERR] Write key failed: %v\n", err)
			} else {
				fmt.Println("   -> client.keys restored successfully (Decoded).")
			}
		}
	} else {
		os.Remove("C:\\Program Files (x86)\\ossec-agent\\client.keys")
	}

	// 6. START & SAVE
	installGozuhService()
	sys.RestartWazuhAgent()
	startGozuhManual()

	config.SaveState(&config.State{
		HardwareHash: hw.Hash,
		Hostname:     targetName,
	})

	fmt.Println("\n>>> INSTALLATION COMPLETE <<<")
}

func unifiedUninstall() {
	fmt.Println(">>> UNINSTALLING... <<<")
	m, _ := mgr.Connect()
	defer m.Disconnect()
	s, err := m.OpenService("GOZUH")
	if err == nil {
		fmt.Println("[1/3] Removing GOZUH Service...")
		s.Control(svc.Stop)
		s.Delete()
		s.Close()
	}

	fmt.Println("[2/3] Uninstalling Wazuh Agent MSI...")
	cmd := exec.Command("msiexec", "/x", sys.MSIFileName, "/qn")
	cmd.Run()

	fmt.Println("[3/3] Cleaning up local state...")
	os.Remove("C:\\Program Files\\GOZUH\\state.json")

	fmt.Println(">>> UNINSTALL COMPLETE <<<")
}

// Helpers
func parseIPFromURL(rawURL string) string {
	cleaned := strings.TrimPrefix(rawURL, "https://")
	cleaned = strings.TrimPrefix(cleaned, "http://")
	if strings.Contains(cleaned, ":") {
		return strings.Split(cleaned, ":")[0]
	}
	return cleaned
}
func runService() { svc.Run("GOZUH", &service.GozuhService{}) }
func installGozuhService() {
	exePath, _ := os.Executable()
	m, _ := mgr.Connect()
	defer m.Disconnect()
	c := mgr.Config{StartType: mgr.StartAutomatic, DisplayName: "GOZUH - Wazuh Agent Companion", Description: "Smart Wazuh Agent Companion"}
	s, err := m.CreateService("GOZUH", exePath, c)
	if err == nil {
		s.Close()
	}
}
func startGozuhManual() {
	m, _ := mgr.Connect()
	defer m.Disconnect()
	s, err := m.OpenService("GOZUH")
	if err == nil {
		s.Start()
		s.Close()
	}
}
