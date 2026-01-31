package service

import (
	"log"
	"os"
	"path/filepath"
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
	log.Println("[GOZUH] Service Started. Watchdog v1.2 Active.")

	for {
		conf, _ := config.LoadConfig()
		api := wazuh.NewClient(conf.WazuhURL, conf.IndexerURL, conf.APIUser, conf.APIPass, conf.IndexerUser, conf.IndexerPass)
		executor := &Executor{API: api, Conf: conf}

		ctx := buildContext(api)
		decision := EvaluateState(ctx)
		executor.ExecuteDecision(decision, ctx)
		time.Sleep(time.Duration(conf.SyncInterval) * time.Second)
	}
}

func buildContext(api *wazuh.Client) *AgentContext {
	ctx := &AgentContext{}
	hw, err := identity.GetIdentity()
	if err != nil {
		log.Printf("[ERR] Hardware scan failed: %v", err)
		return ctx 
	}
	ctx.Hardware = hw
	suffix := "0000000000"
	if len(hw.Hash) > 10 {
		suffix = hw.Hash[len(hw.Hash)-10:]
	}
	host, _ := os.Hostname()
	ctx.TargetName = host + "-" + suffix
	ctx.TargetHash = suffix

	ctx.SvcRunning, _ = sys.IsServiceRunning()
	id, name, err := wazuh.GetLocalAuth()
	if err == nil {
		ctx.HasKey = true
		ctx.LocalID = id
		ctx.LocalName = name
	}

	state, _ := config.LoadState()
	if state != nil {
		ctx.StateHash = state.HardwareHash
	}
	confHash, _ := wazuh.GetHardwareLabel()
	ctx.ConfigHash = confHash
	if ctx.HasKey {
		info, err := api.GetAgentInfo(ctx.LocalID)
		if err == nil {
			ctx.ServerReachable = true
			ctx.ServerAgent = info
			labels, _ := api.GetAgentLabels(ctx.LocalID)
			if labels != nil {
				ctx.ServerHash = labels["hardware_hash"]
			}
		} else {
			if err.Error() == "not_found" {
				ctx.ServerReachable = true 
				ctx.ServerAgent = nil
			} else {
				ctx.ServerReachable = false
			}
		}
	} else {
		if err := api.Authenticate(); err == nil {
			ctx.ServerReachable = true
		}
	}

	return ctx
}

func setupLogging() {
	os.MkdirAll(filepath.Dir(config.LogFile), 0755)
	f, _ := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	log.SetOutput(f)
}