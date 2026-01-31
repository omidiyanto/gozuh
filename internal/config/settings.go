package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const (
	AppDir         = "C:\\Program Files\\GOZUH"
	WazuhDir       = "C:\\Program Files (x86)\\ossec-agent"
	ConfigFile     = AppDir + "\\config.json"
	StateFile      = AppDir + "\\state.json"
	LogFile        = AppDir + "\\service.log"
	WazuhClientKey = WazuhDir + "\\client.keys"
	WazuhConf      = WazuhDir + "\\ossec.conf"
	WazuhService   = "WazuhSvc"
	GozuhService   = "GOZUH"
)

type Config struct {
	WazuhURL     string `json:"wazuh_url"`
	APIUser      string `json:"api_user"`
	APIPass      string `json:"api_pass"`
	IndexerURL   string `json:"indexer_url"`
	IndexerUser  string `json:"indexer_user"`
	IndexerPass  string `json:"indexer_pass"`
	SyncInterval int    `json:"sync_interval"`
}

type State struct {
	HardwareHash string `json:"hardware_hash"`
	Hostname     string `json:"hostname"`
	LastSync     string `json:"last_sync"`
}

func LoadConfig() (*Config, error) {
	// Default Config
	defaultConf := &Config{
		WazuhURL:     "https://192.168.0.230:55000",
		APIUser:      "wazuh-wui",
		APIPass:      "MyS3cr37P450r.*-",
		IndexerURL:   "https://192.168.0.230:9200",
		IndexerUser:  "admin",
		IndexerPass:  "SecretPassword",
		SyncInterval: 60,
	}

	file, err := os.ReadFile(ConfigFile)
	if err != nil {
		return defaultConf, nil
	}
	var conf Config
	if err := json.Unmarshal(file, &conf); err != nil {
		return defaultConf, nil
	}

	if conf.SyncInterval < 10 {
		conf.SyncInterval = 60
	}
	return &conf, nil
}

func LoadState() (*State, error) {
	file, err := os.ReadFile(StateFile)
	if err != nil {
		return nil, err
	}
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