package sys

import (
	"fmt"
	"os"
	"time"
	"gozuh/internal/config"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const WazuhServiceName = "WazuhSvc"
const GozuhServiceName = "GOZUH"

func GetServiceStatus(name string) string {
	m, err := mgr.Connect()
	if err != nil {
		return "SCM_UNAVAILABLE"
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return "NOT_INSTALLED"
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return "QUERY_FAILED"
	}

	switch status.State {
	case svc.Stopped:
		return "STOPPED"
	case svc.StartPending:
		return "START_PENDING"
	case svc.StopPending:
		return "STOP_PENDING"
	case svc.Running:
		return "RUNNING"
	default:
		return "UNKNOWN"
	}
}

func ConnectService(name string) (*mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("gagal connect SCM: %v", err)
	}
	defer m.Disconnect()
	return m.OpenService(name)
}

func IsServiceRunning() (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, nil
	}
	defer m.Disconnect()
	s, err := m.OpenService(WazuhServiceName)
	if err != nil {
		return false, nil
	}
	defer s.Close()
	status, err := s.Query()
	return status.State == svc.Running, nil
}

func StopWazuhService() error {
	m, err := mgr.Connect()
	if err != nil { return err }
	defer m.Disconnect()
	
	s, err := m.OpenService(config.WazuhService)
	if err != nil { return err }
	defer s.Close()
	
	status, _ := s.Query()
	if status.State == svc.Running {
		s.Control(svc.Stop)
		time.Sleep(2 * time.Second)
	}
	return nil
}

func RestartWazuhAgent() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(WazuhServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		s.Control(svc.Stop)
		for i := 0; i < 15; i++ {
			status, _ = s.Query()
			if status.State == svc.Stopped {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}
	return s.Start()
}

func InstallGozuhService() error {
	exePath, err := os.Executable()
	if err != nil { return err }

	m, err := mgr.Connect()
	if err != nil { return err }
	defer m.Disconnect()

	s, err := m.OpenService(GozuhServiceName)
	if err == nil {
		s.Close()
		return nil 
	}

	config := mgr.Config{
		StartType:    mgr.StartAutomatic,
		DisplayName:  "Wazuh | Gozuh - Agent Companion for Wazuh",
		Description:  "Smart Wazuh Agent Lifecycle Manager",
		ErrorControl: mgr.ErrorNormal,
	}

	s, err = m.CreateService(GozuhServiceName, exePath, config)
	if err != nil { return err }
	defer s.Close()
	return nil
}

func StartGozuhService() error {
	m, err := mgr.Connect()
	if err != nil { return err }
	defer m.Disconnect()

	s, err := m.OpenService(GozuhServiceName)
	if err != nil { return err }
	defer s.Close()

	return s.Start()
}

func RemoveGozuhService() error {
	m, err := mgr.Connect()
	if err != nil { return err }
	defer m.Disconnect()

	s, err := m.OpenService(GozuhServiceName)
	if err != nil { return nil } 
	defer s.Close()

	s.Control(svc.Stop)
	return s.Delete()
}