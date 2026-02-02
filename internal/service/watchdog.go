package service

import (
	"log"
	"os"
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
	SetupServiceLogging()
	log.Println("[GOZUH] Service Started.")

	for {
		fInfo, err := os.Stat(config.ServiceLogFile)
		if err == nil && fInfo.Size() > 10*1024*1024 {
			log.Println("[MAINTENANCE] Log file too large. Rotating...")
			SetupServiceLogging()
		}
		conf, _ := config.LoadConfig()
		api := wazuh.NewClient(conf.ManagerURL, conf.IndexerURL, conf.ManagerUser, conf.ManagerPass, conf.IndexerUser, conf.IndexerPass)
		executor := &Executor{API: api, Conf: conf}

		ctx := buildContext(api, conf)
		decision := EvaluateState(ctx)
		executor.ExecuteDecision(decision, ctx)
		time.Sleep(time.Duration(conf.SyncInterval) * time.Second)
	}
}

func buildContext(api *wazuh.Client, conf *config.Config) *AgentContext {
	ctx := &AgentContext{}
	hw, err := identity.GetIdentity(conf.AllowVirtual)
	if err != nil {
		log.Printf("[ERR] Hardware scan failed: %v", err)
		return ctx
	}
	ctx.Hardware = hw
	suffix := "0000000000"
	if len(hw.Hash) > 10 { suffix = hw.Hash[len(hw.Hash)-10:] }
	host, _ := os.Hostname()
	ctx.TargetName = host + "-" + suffix
	ctx.TargetHash = suffix
	ctx.TargetGroup = conf.AgentGroup
	ctx.LocalConfigGroup = conf.AgentGroup

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