package sys

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Pastikan nama file sesuai dengan yang ada di folder Anda
const MSIFileName = "wazuh-agent-4.14.1-1.msi"

// InstallWazuhMSI menjalankan installer dengan Parameter Wajib
func InstallWazuhMSI(managerIP, agentName string) error {
	exePath, _ := os.Executable()
	workingDir := filepath.Dir(exePath)
	msiPath := filepath.Join(workingDir, MSIFileName)

	if _, err := os.Stat(msiPath); os.IsNotExist(err) {
		return fmt.Errorf("file %s tidak ditemukan", MSIFileName)
	}

	fmt.Printf("[MSI] Installing %s...\n", MSIFileName)
	fmt.Printf("      Manager : %s\n", managerIP)
	fmt.Printf("      Name    : %s\n", agentName)

	// Command sesuai request:
	// msiexec.exe /i <PATH> /qn WAZUH_MANAGER='IP' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='NAME'
	cmd := exec.Command("msiexec", "/i", msiPath, "/qn",
		fmt.Sprintf("WAZUH_MANAGER=%s", managerIP),
		"WAZUH_AGENT_GROUP=default",
		fmt.Sprintf("WAZUH_AGENT_NAME=%s", agentName),
		"/norestart",
	)

	// Sembunyikan window console
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("msiexec failed: %v. Output: %s", err, string(output))
	}

	return nil
}