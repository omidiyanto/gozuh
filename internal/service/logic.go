package service

import (
	"log"
	"strings"
	"time"
)

func EvaluateState(ctx *AgentContext) Decision {
	if ctx.StateHash != "" && !strings.EqualFold(ctx.StateHash, ctx.Hardware.Hash) {
		log.Printf("[DIAGNOSE] Local State Corruption. State: %s vs HW: %s", ctx.StateHash, ctx.Hardware.Hash)
		return ActionFixConfig
	}
	if ctx.ConfigHash != "" && !strings.EqualFold(ctx.ConfigHash, ctx.Hardware.Hash) {
		log.Printf("[DIAGNOSE] Wazuh Config Corruption. Label: %s vs HW: %s", ctx.ConfigHash, ctx.Hardware.Hash)
		return ActionFixConfig
	}
	if !ctx.HasKey {
		log.Println("[DIAGNOSE] Case F: Missing Identity Key.")
		return ActionRecovery
	}
	if !ctx.ServerReachable {
		log.Println("[DIAGNOSE] Case B: Network Outage. Entering Standby Mode.")
		return ActionStandby
	}
	if ctx.ServerAgent == nil {
		log.Printf("[DIAGNOSE] Case C: Ghost Agent. Local ID %s not found on server.", ctx.LocalID)
		return ActionSelfHeal
	}
	if ctx.ServerHash != "" && !strings.EqualFold(ctx.ServerHash, ctx.Hardware.Hash) {
		log.Printf("[DIAGNOSE] Case D: Cloning Detected. Server Hash (%s) != Local (%s).", ctx.ServerHash, ctx.Hardware.Hash)
		return ActionMigrate
	}
	if ctx.LocalName != "" && !strings.EqualFold(ctx.LocalName, ctx.TargetName) {
		if !strings.EqualFold(ctx.ServerAgent.Name, ctx.TargetName) {
			log.Printf("[DIAGNOSE] Case E: Hostname Changed. Target: %s vs Current: %s", ctx.TargetName, ctx.ServerAgent.Name)
			return ActionRename
		}
	}
	if ctx.SvcRunning && strings.ToLower(ctx.ServerAgent.Status) == "disconnected" {
		if isOutdated(ctx.ServerAgent.LastKeepAlive, 24*time.Hour) {
			log.Println("[DIAGNOSE] Case G: Zombie Agent.")
			return ActionRestartSvc
		}
	}
	return ActionIdle
}

func isOutdated(timeStr string, threshold time.Duration) bool {
	if timeStr == "" { return true }
	formats := []string{"2006-01-02T15:04:05Z", "2006-01-02 15:04:05"}
	for _, f := range formats {
		t, err := time.Parse(f, timeStr)
		if err == nil { return time.Since(t) > threshold }
	}
	return false 
}