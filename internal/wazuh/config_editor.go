package wazuh

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"gozuh/internal/config"
)

const LabelKey = "hardware_hash"

func getSCARulesPath() string {
	return filepath.Join(config.WazuhDir, "ruleset", "sca")
}

func GetHardwareLabel() (string, error) {
	contentBytes, err := os.ReadFile(config.WazuhConf)
	if err != nil {
		return "", err
	}
	content := string(contentBytes)
	re := regexp.MustCompile(fmt.Sprintf(`<label key="%s">([^<]+)</label>`, LabelKey))
	matches := re.FindStringSubmatch(content)

	if len(matches) >= 2 {
		return matches[1], nil
	}
	return "", nil
}

func DisableCISBenchmarks() error {
	fmt.Println("[HARDENING] Disabling CIS Benchmark policies...")

	files, err := filepath.Glob(filepath.Join(getSCARulesPath(), "cis*.y*ml"))
	if err != nil {
		return fmt.Errorf("failed to scan SCA folder: %v", err)
	}

	for _, file := range files {
		if strings.HasSuffix(file, ".disabled") {
			continue
		}

		newPath := file + ".disabled"
		fmt.Printf("   -> Renaming %s to .disabled\n", filepath.Base(file))
		if err := os.Rename(file, newPath); err != nil {
			fmt.Printf("      [WARN] Failed to rename %s: %v\n", filepath.Base(file), err)
		}
	}
	return nil
}

func ApplyHardening() error {
	contentBytes, err := os.ReadFile(config.WazuhConf)
	if err != nil {
		return err
	}
	content := string(contentBytes)

	reSCA := regexp.MustCompile(`(?s)<sca>.*?</sca>`)
	newContent := reSCA.ReplaceAllStringFunc(content, func(m string) string {
		return strings.Replace(m, "<disabled>yes</disabled>", "<disabled>no</disabled>", 1)
	})

	return os.WriteFile(config.WazuhConf, []byte(newContent), 0644)
}

func UpdateAgentName(newName string) error {
	contentBytes, err := os.ReadFile(config.WazuhConf)
	if err != nil { return err }
	content := string(contentBytes)

	expectedTag := fmt.Sprintf("<agent_name>%s</agent_name>", newName)

	reEnrollment := regexp.MustCompile(`(?s)<enrollment>.*?</enrollment>`)
	enrollmentBlock := reEnrollment.FindString(content)

	var newContent string

	if enrollmentBlock != "" {
		reName := regexp.MustCompile(`<agent_name>.*?</agent_name>`)
		var newEnrollmentBlock string
		if reName.MatchString(enrollmentBlock) {
			newEnrollmentBlock = reName.ReplaceAllString(enrollmentBlock, expectedTag)
		} else {
			newEnrollmentBlock = strings.Replace(enrollmentBlock, "</enrollment>", fmt.Sprintf("  %s\n    </enrollment>", expectedTag), 1)
		}
		newContent = strings.Replace(content, enrollmentBlock, newEnrollmentBlock, 1)
	} else {
		reClient := regexp.MustCompile(`(?s)<client>.*?</client>`)
		newContent = reClient.ReplaceAllStringFunc(content, func(m string) string {
			if strings.Contains(m, "<enrollment>") { return m }
			return strings.Replace(m, "</client>", fmt.Sprintf("  <enrollment>\n      %s\n    </enrollment>\n  </client>", expectedTag), 1)
		})
	}

	return os.WriteFile(config.WazuhConf, []byte(newContent), 0644)
}

func GetConfiguredGroup() (string, error) {
	contentBytes, err := os.ReadFile(config.WazuhConf)
	if err != nil {
		return "", err
	}
	content := string(contentBytes)

	reEnrollment := regexp.MustCompile(`(?s)<enrollment>.*?</enrollment>`)
	enrollmentBlock := reEnrollment.FindString(content)

	if enrollmentBlock != "" {
		reGroup := regexp.MustCompile(`<groups>([^<]+)</groups>`)
		matches := reGroup.FindStringSubmatch(enrollmentBlock)
		if len(matches) >= 2 {
			return strings.TrimSpace(matches[1]), nil
		}
	}
	return "default", nil
}

func UpdateAgentGroup(newGroup string) error {
	if newGroup == "" { newGroup = "default" }
	contentBytes, err := os.ReadFile(config.WazuhConf)
	if err != nil { return err }
	content := string(contentBytes)
	reEnrollment := regexp.MustCompile(`(?s)<enrollment>.*?</enrollment>`)
	enrollmentBlock := reEnrollment.FindString(content)

	var newContent string
	expectedTag := fmt.Sprintf("<groups>%s</groups>", newGroup)

	if enrollmentBlock != "" {
		reGroup := regexp.MustCompile(`<groups>.*?</groups>`)
		var newEnrollmentBlock string
		if reGroup.MatchString(enrollmentBlock) {
			newEnrollmentBlock = reGroup.ReplaceAllString(enrollmentBlock, expectedTag)
		} else {
			newEnrollmentBlock = strings.Replace(enrollmentBlock, "</enrollment>", fmt.Sprintf("  %s\n    </enrollment>", expectedTag), 1)
		}
		newContent = strings.Replace(content, enrollmentBlock, newEnrollmentBlock, 1)
	} else {
		reClient := regexp.MustCompile(`(?s)<client>.*?</client>`)
		newContent = reClient.ReplaceAllStringFunc(content, func(m string) string {
			return strings.Replace(m, "</client>", fmt.Sprintf("  <enrollment>\n      %s\n    </enrollment>\n  </client>", expectedTag), 1)
		})
	}

	return os.WriteFile(config.WazuhConf, []byte(newContent), 0644)
}

func EnsureHardwareLabel(hash string) (bool, error) {
	contentBytes, err := os.ReadFile(config.WazuhConf)
	if err != nil { return false, err }
	content := string(contentBytes)

	correctLine := fmt.Sprintf(`<label key="%s">%s</label>`, LabelKey, hash)

	if strings.Contains(content, correctLine) {
		return false, nil
	}

	fmt.Println("[CONFIG] Fixing hardware_hash labels...")

	reAnyHash := regexp.MustCompile(fmt.Sprintf(`\s*<label key="%s">.*?</label>`, LabelKey))
	cleanContent := reAnyHash.ReplaceAllString(content, "")

	var finalContent string
	if strings.Contains(cleanContent, "</labels>") {
		reEndLabels := regexp.MustCompile(`\s*</labels>`)
		finalContent = reEndLabels.ReplaceAllString(cleanContent, fmt.Sprintf("\n    %s\n  </labels>", correctLine))
	} else {
		reEndConfig := regexp.MustCompile(`\s*</ossec_config>`)
		block := fmt.Sprintf("\n  <labels>\n    %s\n  </labels>\n</ossec_config>", correctLine)
		finalContent = reEndConfig.ReplaceAllString(cleanContent, block)
	}

	if err := os.WriteFile(config.WazuhConf, []byte(finalContent), 0644); err != nil {
		return false, err
	}
	return true, nil
}

func SetRemoteCommands(enable bool) error {
	val := "0"
	if enable { val = "1" }
	if _, err := os.Stat(config.WazuhLocalInternal); os.IsNotExist(err) { os.Create(config.WazuhLocalInternal) }

	contentBytes, err := os.ReadFile(config.WazuhLocalInternal)
	if err != nil { return err }
	content := string(contentBytes)

	settings := map[string]string{
		"sca.remote_commands":           val,
		"wazuh_command.remote_commands": val,
	}

	newContent := content
	for key, value := range settings {
		targetLine := fmt.Sprintf("%s=%s", key, value)
		re := regexp.MustCompile(fmt.Sprintf(`(?m)^%s=.*`, regexp.QuoteMeta(key)))
		
		if re.MatchString(newContent) {
			newContent = re.ReplaceAllString(newContent, targetLine)
		} else {
			if len(newContent) > 0 && !strings.HasSuffix(newContent, "\n") {
				newContent += "\n"
			}
			newContent += targetLine + "\n"
		}
	}

	if newContent != content {
		fmt.Printf("[CONFIG] Updating local_internal_options.conf (Remote Commands: %s)...\n", val)
		return os.WriteFile(config.WazuhLocalInternal, []byte(newContent), 0644)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, _ := os.Open(src)
	defer in.Close()
	out, _ := os.Create(dst)
	defer out.Close()
	_, err := io.Copy(out, in)
	return err
}

func WipeLocalSyscheck() error {
	contentBytes, err := os.ReadFile(config.WazuhConf)
	if err != nil { return err }
	content := string(contentBytes)
	initialContent := content
	targetSyscheck := `<syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
	<!-- Default files to be monitored. -->
    <directories recursion_level="0" restrict="regedit.exe$|system.ini$|win.ini$">%WINDIR%</directories>
    <directories recursion_level="0" restrict="at.exe$|attrib.exe$|cacls.exe$|cmd.exe$|eventcreate.exe$|ftp.exe$|lsass.exe$|net.exe$|net1.exe$|netsh.exe$|reg.exe$|regedt32.exe|regsvr32.exe|runas.exe|sc.exe|schtasks.exe|sethc.exe|subst.exe$">%WINDIR%\SysNative</directories>
    <directories recursion_level="0">%WINDIR%\SysNative\drivers\etc</directories>
    <directories recursion_level="0" restrict="WMIC.exe$">%WINDIR%\SysNative\wbem</directories>
    <directories recursion_level="0" restrict="powershell.exe$">%WINDIR%\SysNative\WindowsPowerShell\v1.0</directories>
    <directories recursion_level="0" restrict="winrm.vbs$">%WINDIR%\SysNative</directories>
    <!-- 32-bit programs. -->
    <directories recursion_level="0" restrict="at.exe$|attrib.exe$|cacls.exe$|cmd.exe$|eventcreate.exe$|ftp.exe$|lsass.exe$|net.exe$|net1.exe$|netsh.exe$|reg.exe$|regedit.exe$|regedt32.exe$|regsvr32.exe$|runas.exe$|sc.exe$|schtasks.exe$|sethc.exe$|subst.exe$">%WINDIR%\System32</directories>
    <directories recursion_level="0">%WINDIR%\System32\drivers\etc</directories>
    <directories recursion_level="0" restrict="WMIC.exe$">%WINDIR%\System32\wbem</directories>
    <directories recursion_level="0" restrict="powershell.exe$">%WINDIR%\System32\WindowsPowerShell\v1.0</directories>
    <directories recursion_level="0" restrict="winrm.vbs$">%WINDIR%\System32</directories>
    <directories realtime="yes">%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    <ignore>%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini</ignore>
    <ignore type="sregex">.log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$</ignore>
    <windows_audit_interval>60</windows_audit_interval>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>`

	reSyscheck := regexp.MustCompile(`(?s)<syscheck>.*?</syscheck>`)
	newContent := reSyscheck.ReplaceAllString(content, targetSyscheck)
	if newContent != initialContent {
		fmt.Println("[HARDENING] Applying optimized Syscheck (FIM) configuration...")
		return os.WriteFile(config.WazuhConf, []byte(newContent), 0644)
	}
	return nil
}