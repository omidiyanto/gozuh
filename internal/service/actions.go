package service

import (
	"encoding/base64"
	"gozuh/internal/config"
	"gozuh/internal/sys"
	"gozuh/internal/wazuh"
	"log"
	"os"
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
			if d == ActionRename {
				e.API.DeleteAgent(ctx.LocalID)
			}
		}
		
		os.Remove(config.WazuhClientKey)
		e.performRecovery(ctx)

	case ActionRecovery:
		log.Println("[ACTION] Performing Fresh/Recovery Installation...")
		e.performRecovery(ctx)
	}
}

func (e *Executor) performRecovery(ctx *AgentContext) {
	sys.StopWazuhService()

	candidates, err := e.API.GetAgentCandidates(ctx.TargetHash)
	var recoveryID, recoveryKey string

	if err == nil {
		for _, c := range candidates {
			if c.Name == ctx.TargetName && ctx.LocalID != "" { continue }

			verified, _ := e.API.VerifyHashInIndexer(c.ID, ctx.Hardware.Hash)
			if verified {
				log.Printf("[RECOVERY] Found history match: %s (ID: %s)", c.Name, c.ID)
				if c.Name != ctx.TargetName {
					log.Println("[RECOVERY] Name mismatch on recovery. Deleting old record first.")
					e.API.DeleteAgent(c.ID)
					break
				} else {
					key, kErr := e.API.GetAgentKey(c.ID)
					if kErr == nil {
						recoveryID = c.ID
						recoveryKey = key
					}
				}
				break
			}
		}
	}

	if recoveryID != "" && recoveryKey != "" {
		rawKey, _ := base64.StdEncoding.DecodeString(recoveryKey)
		os.WriteFile(config.WazuhClientKey, rawKey, 0644)
		log.Println("[SUCCESS] Identity Restored from Server.")
	} else {
		log.Println("[FRESH] No history found. Treating as new agent.")
		wazuh.UpdateAgentName(ctx.TargetName)
	}

	wazuh.EnsureHardwareLabel(ctx.Hardware.Hash)
	wazuh.UpdateAgentName(ctx.TargetName)
	sys.RestartWazuhAgent()

	config.SaveState(&config.State{
		HardwareHash: ctx.Hardware.Hash,
		Hostname:     ctx.TargetName,
	})
}