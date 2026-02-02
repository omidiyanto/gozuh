package service

import (
	"log"
	"sort"
	"strings"
	"time"
	"gozuh/internal/wazuh"
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
	serverGroups := ctx.ServerAgent.Group
	sort.Strings(serverGroups)
	serverGroupStr := strings.Join(serverGroups, ",")
	if serverGroupStr == "" { serverGroupStr = "default" }
	localGroupsRaw := strings.Split(ctx.LocalConfigGroup, ",")
	var localGroupsClean []string
	for _, g := range localGroupsRaw {
		if t := strings.TrimSpace(g); t != "" {
			localGroupsClean = append(localGroupsClean, t)
		}
	}
	if len(localGroupsClean) == 0 { localGroupsClean = []string{"default"} }
	sort.Strings(localGroupsClean)
	localGroupStr := strings.Join(localGroupsClean, ",")
	ossecRaw, _ := wazuh.GetConfiguredGroup()
	ossecGroupsRaw := strings.Split(ossecRaw, ",")
	var ossecGroupsClean []string
	for _, g := range ossecGroupsRaw {
		if t := strings.TrimSpace(g); t != "" {
			ossecGroupsClean = append(ossecGroupsClean, t)
		}
	}
	if len(ossecGroupsClean) == 0 { ossecGroupsClean = []string{"default"} }
	sort.Strings(ossecGroupsClean)
	ossecGroupStr := strings.Join(ossecGroupsClean, ",")
	configMismatch := !strings.EqualFold(serverGroupStr, localGroupStr)
	ossecMismatch := !strings.EqualFold(serverGroupStr, ossecGroupStr)

	if configMismatch || ossecMismatch {
		if configMismatch {
			log.Printf("[DIAGNOSE] Config Drift Detected (JSON). Server: [%s] vs Local: [%s].", serverGroupStr, localGroupStr)
		}
		if ossecMismatch {
			log.Printf("[DIAGNOSE] Config Tampering Detected (XML). Server: [%s] vs Ossec: [%s].", serverGroupStr, ossecGroupStr)
		}
		return ActionSyncLocal
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