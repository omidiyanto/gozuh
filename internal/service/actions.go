package service

import (
	"encoding/base64"
	"gozuh/internal/config"
	"gozuh/internal/sys"
	"gozuh/internal/wazuh"
	"log"
	"os"
	"strings"
)

type Executor struct {
	API  *wazuh.Client
	Conf *config.Config
}

func (e *Executor) ExecuteDecision(d Decision, ctx *AgentContext) {
	switch d {
	case ActionStandby, ActionIdle:
		if d == ActionIdle && !ctx.SvcRunning {
			sys.RestartWazuhAgent()
		}
		return

	case ActionFixConfig:
		log.Println("[ACTION] Fixing Local Configuration Integrity...")
		config.SaveState(&config.State{
			HardwareHash: ctx.Hardware.Hash,
			Hostname:     ctx.TargetName,
		})
		wazuh.EnsureHardwareLabel(ctx.Hardware.Hash)
		wazuh.UpdateAgentName(ctx.TargetName)
		sys.RestartWazuhAgent()
		log.Println("[SUCCESS] Configuration Repaired.")

	case ActionRestartSvc:
		log.Println("[ACTION] Restarting Wazuh Service (Zombie Fix)...")
		sys.RestartWazuhAgent()

	case ActionMigrate:
		log.Printf("[ACTION] Cloning Detected. Dropping invalid identity (ID: %s)...", ctx.LocalID)
		os.Remove(config.WazuhClientKey)
		e.performRecovery(ctx)

	case ActionRename, ActionSelfHeal:
		log.Printf("[ACTION] Executing %s sequence...", d)
		if ctx.LocalID != "" {
			e.API.DeleteAgent(ctx.LocalID)
		}
		os.Remove(config.WazuhClientKey)
		e.performRecovery(ctx)

	case ActionSyncLocal:
		log.Println("[ACTION] Config Drift Detected. Synchronizing Local Configuration with Server State...")
		serverGroups := strings.Join(ctx.ServerAgent.Group, ",")
		if serverGroups == "" { serverGroups = "default" }
		currentConf, _ := config.LoadConfig()
		log.Printf("[SYNC] Correcting agent_group. Old: [%s] -> New: [%s]", currentConf.AgentGroup, serverGroups)
		currentConf.AgentGroup = serverGroups
		if err := config.SaveConfig(currentConf); err != nil {
			log.Printf("[ERR] Failed to update config.json: %v", err)
		}
		if err := wazuh.UpdateAgentGroup(serverGroups); err != nil {
			log.Printf("[ERR] Failed to update ossec.conf: %v", err)
		}
		sys.RestartWazuhAgent()
		log.Println("[SUCCESS] Synchronization Complete (Service Restarted).")

	case ActionRecovery:
		log.Println("[ACTION] Performing Fresh/Recovery Installation...")
		e.performRecovery(ctx)
	}
}

func (e *Executor) performRecovery(ctx *AgentContext) {
	sys.StopService(config.WazuhService)
	candidates, err := e.API.GetAgentCandidates(ctx.TargetHash)
	var recoveryID, recoveryKey string

	if err == nil {
		for _, c := range candidates {
			if c.Name == ctx.TargetName && ctx.LocalID != "" { continue }

			verified, _ := e.API.VerifyHashInIndexer(c.ID, ctx.Hardware.Hash)
			if verified {
				log.Printf("[RECOVERY] Found history match: %s (ID: %s)", c.Name, c.ID)
				if c.Name != ctx.TargetName {
					log.Printf("[RECOVERY] Name Mismatch. Deleting old record %s...", c.ID)
					e.API.DeleteAgent(c.ID)
					continue
				} else {
					key, kErr := e.API.GetAgentKey(c.ID)
					if kErr == nil {
						recoveryID, recoveryKey = c.ID, key
					}
					break
				}
			}
		}
	}

	if recoveryID != "" {
		raw, _ := base64.StdEncoding.DecodeString(recoveryKey)
		os.WriteFile(config.WazuhClientKey, raw, 0644)
		log.Println("[SUCCESS] Identity Restored.")
	} else {
		log.Println("[FRESH] No valid history found. Registering new agent...")
		wazuh.UpdateAgentGroup(ctx.TargetGroup)
		wazuh.UpdateAgentName(ctx.TargetName)
	}

	wazuh.EnsureHardwareLabel(ctx.Hardware.Hash)
	sys.RestartWazuhAgent()
	config.SaveState(&config.State{HardwareHash: ctx.Hardware.Hash, Hostname: ctx.TargetName})
}