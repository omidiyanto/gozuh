package wazuh

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	OssecPath     = "C:\\Program Files (x86)\\ossec-agent"
	OssecConfPath = OssecPath + "\\ossec.conf"
	SCARulesPath  = OssecPath + "\\ruleset\\sca"
	LabelKey      = "hardware_hash"
)

func GetHardwareLabel() (string, error) {
	contentBytes, err := os.ReadFile(OssecConfPath)
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

	files, err := filepath.Glob(filepath.Join(SCARulesPath, "cis*.y*ml"))
	if err != nil {
		return fmt.Errorf("gagal scan folder SCA: %v", err)
	}

	for _, file := range files {
		if strings.HasSuffix(file, ".disabled") {
			continue
		}

		newPath := file + ".disabled"
		fmt.Printf("   -> Renaming %s to .disabled\n", filepath.Base(file))
		if err := os.Rename(file, newPath); err != nil {
			fmt.Printf("      [WARN] Gagal rename %s: %v\n", filepath.Base(file), err)
		}
	}
	return nil
}

func ApplyHardening() error {
	contentBytes, err := os.ReadFile(OssecConfPath)
	if err != nil {
		return err
	}
	content := string(contentBytes)

	reSCA := regexp.MustCompile(`(?s)<sca>.*?</sca>`)
	newContent := reSCA.ReplaceAllStringFunc(content, func(m string) string {
		return strings.Replace(m, "<disabled>no</disabled>", "<disabled>yes</disabled>", 1)
	})

	return os.WriteFile(OssecConfPath, []byte(newContent), 0644)
}

func UpdateAgentName(newName string) error {
	contentBytes, err := os.ReadFile(OssecConfPath)
	if err != nil {
		return err
	}
	content := string(contentBytes)

	expectedTag := fmt.Sprintf("<agent_name>%s</agent_name>", newName)
	reName := regexp.MustCompile(`<agent_name>.*?</agent_name>`)

	var newContent string
	if reName.MatchString(content) {
		newContent = reName.ReplaceAllString(content, expectedTag)
	} else {
		newContent = strings.Replace(content, "<enrollment>", "<enrollment>\n      "+expectedTag, 1)
	}
	return os.WriteFile(OssecConfPath, []byte(newContent), 0644)
}

func EnsureHardwareLabel(hash string) (bool, error) {
	contentBytes, err := os.ReadFile(OssecConfPath)
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

	if err := os.WriteFile(OssecConfPath, []byte(finalContent), 0644); err != nil {
		return false, err
	}
	return true, nil
}

func copyFile(src, dst string) error {
	in, _ := os.Open(src)
	defer in.Close()
	out, _ := os.Create(dst)
	defer out.Close()
	_, err := io.Copy(out, in)
	return err
}