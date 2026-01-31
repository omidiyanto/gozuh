package service

import (
	"gozuh/internal/identity"
	"gozuh/internal/wazuh"
)

type Decision string

const (
	ActionIdle       Decision = "IDLE"
	ActionStandby    Decision = "STANDBY"
	ActionFixConfig  Decision = "FIX_CONFIG" 
	ActionSelfHeal   Decision = "SELF_HEAL"
	ActionMigrate    Decision = "MIGRATE"
	ActionRename     Decision = "RENAME"
	ActionRecovery   Decision = "RECOVERY"
	ActionRestartSvc Decision = "RESTART_SVC"
)

type AgentContext struct {
	Hardware   *identity.HardwareInfo
	TargetName string
	TargetHash string

	LocalID    string
	LocalName  string
	HasKey     bool
	SvcRunning bool

	StateHash  string
	ConfigHash string

	ServerReachable bool
	ServerAgent     *wazuh.AgentInfo
	ServerHash      string
}