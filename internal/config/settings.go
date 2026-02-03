package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

var (
	AppDir             string 
	WazuhDir           string 
	ConfigFile         string 
	StateFile          string 
	ServiceLogFile     string
	WazuhClientKey     string
	WazuhConf          string
	WazuhLocalInternal string
)

const (
	WazuhService = "WazuhSvc"
	GozuhService = "GOZUH"
)

type Config struct {
	ManagerURL    string `json:"manager_url"`
	ManagerUser   string `json:"manager_user"`
	ManagerPass   string `json:"manager_pass"`
	IndexerURL    string `json:"indexer_url"`
	IndexerUser   string `json:"indexer_user"`
	IndexerPass   string `json:"indexer_pass"`
	AgentGroup    string `json:"agent_group"`
	InstallerName string `json:"installer_name"`
	DisableCIS    bool   `json:"disable_cis"`
	AllowVirtual  bool   `json:"allow_virtual"`
	SyncInterval  int    `json:"sync_interval"`
	RemoteCommand bool   `json:"remote_command"`
}

type State struct {
	HardwareHash string `json:"hardware_hash"`
	Hostname     string `json:"hostname"`
	LastSync     string `json:"last_sync"`
}

func init() {
	exe, _ := os.Executable()
	AppDir = filepath.Dir(exe)
	ConfigFile = filepath.Join(AppDir, "config.json")
	StateFile = filepath.Join(AppDir, "state.json")
	ServiceLogFile = filepath.Join(AppDir, "service.log") 
	WazuhDir = detectWazuhPath()
	WazuhClientKey = filepath.Join(WazuhDir, "client.keys")
	WazuhConf = filepath.Join(WazuhDir, "ossec.conf")
	WazuhLocalInternal = filepath.Join(WazuhDir, "local_internal_options.conf")
}

func detectWazuhPath() string {
	if x86 := os.Getenv("ProgramFiles(x86)"); x86 != "" {
		return filepath.Join(x86, "ossec-agent")
	}
	return "C:\\Program Files\\ossec-agent"
}

func LoadConfig() (*Config, error) {
	defaultConf := &Config{
		SyncInterval:  60,
		AgentGroup:    "default",
		DisableCIS:    true,
		AllowVirtual:  false,
		RemoteCommand: true, 
	}

	file, err := os.ReadFile(ConfigFile)
	if err != nil {
		return defaultConf, nil
	}

	type encryptedConfig struct {
		*Config
	}
	var rawConf encryptedConfig
	rawConf.Config = defaultConf

	if err := json.Unmarshal(file, &rawConf); err != nil {
		return defaultConf, nil
	}

	if rawConf.ManagerPass != "" {
		dec, _ := Decrypt(rawConf.ManagerPass)
		rawConf.ManagerPass = dec
	}
	if rawConf.IndexerPass != "" {
		dec, _ := Decrypt(rawConf.IndexerPass)
		rawConf.IndexerPass = dec
	}
	if rawConf.IndexerURL == "" { rawConf.IndexerURL = rawConf.ManagerURL }
	if rawConf.IndexerUser == "" { rawConf.IndexerUser = rawConf.ManagerUser }
	if rawConf.IndexerPass == "" { rawConf.IndexerPass = rawConf.ManagerPass }
	if rawConf.SyncInterval < 10 { rawConf.SyncInterval = 60 }

	return rawConf.Config, nil
}

func SaveConfig(c *Config) error {
	EnsureDir(ConfigFile)
	saveConf := *c
	encMgrPass, _ := Encrypt(c.ManagerPass)
	encIdxPass, _ := Encrypt(c.IndexerPass)

	saveConf.ManagerPass = encMgrPass
	saveConf.IndexerPass = encIdxPass

	data, _ := json.MarshalIndent(saveConf, "", "  ")
	return os.WriteFile(ConfigFile, data, 0644)
}

func LoadState() (*State, error) {
	file, err := os.ReadFile(StateFile)
	if err != nil { return nil, err }
	var state State
	json.Unmarshal(file, &state)
	return &state, nil
}

func SaveState(s *State) error {
	EnsureDir(StateFile)
	s.LastSync = time.Now().Format(time.RFC3339)
	data, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(StateFile, data, 0644)
}

func EnsureDir(path string) {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}
}