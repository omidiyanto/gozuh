package sys

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func InstallWazuhMSI(installerPath, managerIP, agentName, groupName string) error {
	if _, err := os.Stat(installerPath); os.IsNotExist(err) {
		return fmt.Errorf("installer file not found at: %s", installerPath)
	}
	fmt.Printf("[MSI] Installing %s...\n", filepath.Base(installerPath))
	fmt.Printf("      Manager : %s\n", managerIP)
	fmt.Printf("      Name    : %s\n", agentName)
	fmt.Printf("      Group   : %s\n", groupName)
	args := []string{
		"/i", installerPath, "/qn",
		fmt.Sprintf("WAZUH_MANAGER=%s", managerIP),
		fmt.Sprintf("WAZUH_AGENT_NAME=%s", agentName),
		"/norestart",
	}
	if groupName != "" {
		args = append(args, fmt.Sprintf("WAZUH_AGENT_GROUP=%s", groupName))
	} else {
		args = append(args, "WAZUH_AGENT_GROUP=default")
	}
	cmd := exec.Command("msiexec", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("msiexec failed: %v. Output: %s", err, string(output))
	}
	return nil
}