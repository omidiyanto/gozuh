package service

import (
	"encoding/base64"
	"fmt"
	"gozuh/internal/config"
	"gozuh/internal/identity"
	"gozuh/internal/sys"
	"gozuh/internal/wazuh"
	"log"
	"os"
	"os/exec"
	"strings"
)

func RunInstall() {
	fmt.Println(">>> STARTING SMART INSTALLATION (SUFFIX STRATEGY) <<<")

	hw, err := identity.GetIdentity()
	if err != nil {
		log.Fatalf("[FATAL] Hardware Error: %v", err)
	}

	gozuhStatus := sys.GetServiceStatus("GOZUH")
	wazuhStatus := sys.GetServiceStatus("WazuhSvc")
	
	state, _ := config.LoadState()
	stateValid := (state != nil && state.HardwareHash == hw.Hash)
	
	keyExists := false
	if _, err := os.Stat(config.WazuhClientKey); err == nil { keyExists = true }

	confLabel, _ := wazuh.GetHardwareLabel()
	confValid := (confLabel == hw.Hash)

	if gozuhStatus == "RUNNING" && wazuhStatus == "RUNNING" && stateValid && keyExists && confValid {
		fmt.Println("[SKIP] System is fully HEALTHY and CONFIG MATCH.")
		fmt.Printf("        - Service  : RUNNING\n")
		fmt.Printf("        - Identity : MATCH (%s)\n", hw.Hash[:10])
		return
	}

	fmt.Println("[INFO] Health check failed or component missing. Proceeding to Install/Heal...")

	conf, _ := config.LoadConfig()
	api := wazuh.NewClient(conf.WazuhURL, conf.IndexerURL, conf.APIUser, conf.APIPass, conf.IndexerUser, conf.IndexerPass)
	managerIP := strings.Split(strings.TrimPrefix(strings.TrimPrefix(conf.WazuhURL, "https://"), "http://"), ":")[0]

	suffix := "0000000000"
	if len(hw.Hash) > 10 { suffix = hw.Hash[len(hw.Hash)-10:] }
	
	rawHost, _ := os.Hostname()
	targetName := fmt.Sprintf("%s-%s", strings.ToLower(rawHost), suffix)
	fmt.Printf("[INFO] Target Identity: %s\n", targetName)

	var recoveryKeyB64, recoveryID, recoveryName string
	fmt.Println("[STEP 1/5] Searching for Existing Owner...")
	candidates, _ := api.GetAgentCandidates(suffix)

	for _, c := range candidates {
		isMatch := false
		labels, err := api.GetAgentLabels(c.ID)
		if err == nil && strings.EqualFold(labels["hardware_hash"], hw.Hash) {
			isMatch = true
		} else {
			verified, _ := api.VerifyHashInIndexer(c.ID, hw.Hash)
			if verified { isMatch = true }
		}

		if isMatch {
			fmt.Printf("   -> FOUND MATCH: Agent '%s' (ID: %s)\n", c.Name, c.ID)
			if c.Name != targetName {
				fmt.Printf("   -> NAME MISMATCH. Deleting old record to allow rename...\n")
				api.DeleteAgent(c.ID)
			} else {
				fmt.Println("   -> PERFECT MATCH. Fetching Key...")
				key, err := api.GetAgentKey(c.ID)
				if err == nil {
					recoveryKeyB64 = key
					recoveryID = c.ID
					recoveryName = c.Name
				}
			}
			break
		}
	}

	if recoveryID == "" {
		fmt.Println("   -> No valid owner found. Proceeding with FRESH INSTALL.")
	}

	fmt.Println("[STEP 2/5] Checking Wazuh Agent MSI...")
	if wazuhStatus == "NOT_INSTALLED" {
		fmt.Println("   -> Installing MSI...")
		if err := sys.InstallWazuhMSI(managerIP, targetName); err != nil {
			log.Fatalf("[FATAL] MSI Install Failed: %v", err)
		}
	} else {
		fmt.Println("   -> MSI already installed.")
	}
	
	sys.StopWazuhService()

	fmt.Println("[STEP 3/5] Applying Hardening & Configuration...")
	wazuh.DisableCISBenchmarks()
	wazuh.EnsureHardwareLabel(hw.Hash)
	wazuh.ApplyHardening()
	wazuh.UpdateAgentName(targetName)

	fmt.Println("[STEP 4/5] Setting up Identity Keys...")
	localID, _, _ := wazuh.GetLocalAuth()
	if localID == recoveryID && recoveryID != "" {
		fmt.Println("   -> Key matches server record. Skipping restore.")
	} else if recoveryKeyB64 != "" {
		fmt.Printf("   -> Restoring session key for agent '%s' (ID: %s)...\n", recoveryName, recoveryID)
		rawKeyBytes, err := base64.StdEncoding.DecodeString(recoveryKeyB64)
		if err == nil {
			os.WriteFile(config.WazuhClientKey, rawKeyBytes, 0644)
		}
	} else {
		if keyExists && recoveryID == "" {
			fmt.Println("   -> Removing orphan key to allow fresh registration.")
			os.Remove(config.WazuhClientKey)
		}
	}
	fmt.Println("[STEP 5/5] Finalizing Services...")

	sys.RestartWazuhAgent()
	if gozuhStatus == "NOT_INSTALLED" {
		fmt.Println("   -> Installing GOZUH Service...")
		if err := sys.InstallGozuhService(); err != nil {
			fmt.Printf("   [WARN] Service install failed: %v\n", err)
		}
		sys.StartGozuhService()
	} else {
		fmt.Println("   -> Restarting Gozuh Service...")
		m, _ := sys.ConnectService("GOZUH")
		if m != nil {
			sys.RemoveGozuhService() 
			sys.InstallGozuhService()
			sys.StartGozuhService()
			m.Close()
		}
	}

	config.SaveState(&config.State{
		HardwareHash: hw.Hash,
		Hostname:     targetName,
	})

	fmt.Println("\n>>> INSTALLATION COMPLETE <<<")
}

func RunDebug() {
	fmt.Println("\n========================================")
	fmt.Println("   GOZUH SYSTEM DEBUG INFORMATION")
	fmt.Println("========================================")

	info, err := identity.GetIdentity()
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
	fmt.Printf(" MAC       : %s\n", info.MAC)
	fmt.Printf(" FULL HASH : %s\n", info.Hash)
	fmt.Printf(" SUFFIX    : %s\n", suffix)
	fmt.Printf(" NAME REQ  : %s\n", targetName)

	localWazuhStatus := sys.GetServiceStatus("WazuhSvc")
	gozuhStatus := sys.GetServiceStatus("GOZUH")
	fmt.Println("\n[LOCAL STATUS]")
	fmt.Printf(" Wazuh Agent (WazuhSvc) : %s\n", localWazuhStatus)
	fmt.Printf(" Gozuh Service          : %s\n", gozuhStatus)

	fmt.Println("\n[SERVER DIAGNOSTICS]")
	conf, _ := config.LoadConfig()
	api := wazuh.NewClient(conf.WazuhURL, conf.IndexerURL, conf.APIUser, conf.APIPass, conf.IndexerUser, conf.IndexerPass)
	
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
	fmt.Println(">>> STARTING ASSET DECOMMISSION (PURGE) <<<")
	conf, _ := config.LoadConfig()
	api := wazuh.NewClient(conf.WazuhURL, conf.IndexerURL, conf.APIUser, conf.APIPass, conf.IndexerUser, conf.IndexerPass)
	hw, _ := identity.GetIdentity()
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
	fmt.Println(">>> UNINSTALLING... <<<")
	sys.RemoveGozuhService()
	exec.Command("msiexec", "/x", "wazuh-agent-4.14.1-1.msi", "/qn").Run()
	os.Remove(config.StateFile)
	fmt.Println(">>> UNINSTALL COMPLETE <<<")
}