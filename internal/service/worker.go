package service

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gozuh/internal/config"
	"gozuh/internal/identity"
	"gozuh/internal/sys"
	"gozuh/internal/wazuh"

	"golang.org/x/sys/windows/svc"
)

type GozuhService struct{}

func (m *GozuhService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	go m.RunLoop()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		c := <-r
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
}

func (m *GozuhService) RunLoop() {
	setupLogging()
	log.Println("[GOZUH] Identity Guard Active.")

	for {
		conf, _ := config.LoadConfig()
		api := wazuh.NewClient(conf.WazuhURL, conf.IndexerURL, conf.APIUser, conf.APIPass, conf.IndexerUser, conf.IndexerPass)

		hw, err := identity.GetIdentity()
		if err != nil {
			time.Sleep(10 * time.Second)
			continue
		}

		rawHost, _ := os.Hostname()
		suffix := "0000000000"
		if len(hw.Hash) > 10 {
			suffix = hw.Hash[len(hw.Hash)-10:]
		}
		targetName := strings.ToLower(fmt.Sprintf("%s-%s", rawHost, suffix))

		if running, _ := sys.IsServiceRunning(); !running {
			log.Println("[WATCHDOG] Restarting Wazuh Agent...")
			sys.RestartWazuhAgent()
		}

		labelChanged, _ := wazuh.EnsureHardwareLabel(hw.Hash)
		wazuh.UpdateAgentName(targetName)

		state, err := config.LoadState()
		isOutOfSync := false
		if err != nil {
			isOutOfSync = true
		} else if state.Hostname != targetName || state.HardwareHash != hw.Hash || labelChanged {
			isOutOfSync = true
		}

		if isOutOfSync {
			log.Printf("[MIGRATION] Syncing identity...")

			s, err := sys.ConnectService("WazuhSvc")
			if err == nil {
				s.Control(svc.Stop)
				s.Close()
				time.Sleep(3 * time.Second)
			}

			if state != nil && state.Hostname != "" && state.Hostname != targetName {
				log.Printf("[CLEANUP] Removing old name: %s", state.Hostname)
				if id, _ := api.GetAgentByName(state.Hostname); id != "" {
					api.DeleteAgent(id)
				}
			}

			candidates, _ := api.GetAgentCandidates(suffix)
			for _, can := range candidates {
				if can.Name == targetName {
					continue
				}

				labels, err := api.GetAgentLabels(can.ID)
				isDuplicate := false
				if err == nil && strings.EqualFold(labels["hardware_hash"], hw.Hash) {
					isDuplicate = true
				} else {
					match, _ := api.VerifyHashInIndexer(can.ID, hw.Hash)
					if match {
						isDuplicate = true
					}
				}

				if isDuplicate {
					log.Printf("[CLEANUP] Removing duplicate: %s (ID: %s)", can.Name, can.ID)
					api.DeleteAgent(can.ID)
				}
			}

			os.Remove("C:\\Program Files (x86)\\ossec-agent\\client.keys")
			wazuh.UpdateAgentName(targetName)

			if id, _ := api.GetAgentByName(targetName); id != "" {
				keyB64, err := api.GetAgentKey(id)
				if err == nil {
					rawKey, decodeErr := base64.StdEncoding.DecodeString(keyB64)
					if decodeErr == nil {
						keyPath := "C:\\Program Files (x86)\\ossec-agent\\client.keys"
						os.WriteFile(keyPath, rawKey, 0644)
						log.Println("[RECOVERY] Key restored (Decoded).")
					} else {
						log.Printf("[ERROR] Base64 decode failed: %v", decodeErr)
					}
				}
			}

			sys.RestartWazuhAgent()
			config.SaveState(&config.State{HardwareHash: hw.Hash, Hostname: targetName})
			log.Println("[SUCCESS] Identity Synced.")
		}
		time.Sleep(time.Duration(conf.SyncInterval) * time.Second)
	}
}

func setupLogging() {
	logPath := "C:\\Program Files\\GOZUH\\service.log"
	os.MkdirAll(filepath.Dir(logPath), 0755)
	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	log.SetOutput(f)
}
