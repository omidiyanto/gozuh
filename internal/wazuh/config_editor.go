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

// DisableCISBenchmarks me-rename file policy CIS bawaan agar tidak dijalankan
func DisableCISBenchmarks() error {
	fmt.Println("[HARDENING] Disabling CIS Benchmark policies...")
	
	// Cari semua file yang diawali "cis" dan diakhiri ".yaml" atau ".yml"
	files, err := filepath.Glob(filepath.Join(SCARulesPath, "cis*.y*ml"))
	if err != nil {
		return fmt.Errorf("gagal scan folder SCA: %v", err)
	}

	for _, file := range files {
		// Skip jika sudah disabled
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

// ApplyHardening menonaktifkan fitur SCA via Config (Backup plan)
func ApplyHardening() error {
	contentBytes, err := os.ReadFile(OssecConfPath)
	if err != nil { return err }
	content := string(contentBytes)

	// Disable SCA block in config
	reSCA := regexp.MustCompile(`(?s)<sca>.*?</sca>`)
	newContent := reSCA.ReplaceAllStringFunc(content, func(m string) string {
		return strings.Replace(m, "<disabled>no</disabled>", "<disabled>yes</disabled>", 1)
	})

	return os.WriteFile(OssecConfPath, []byte(newContent), 0644)
}

// UpdateAgentName mengupdate <agent_name>
func UpdateAgentName(newName string) error {
	contentBytes, err := os.ReadFile(OssecConfPath)
	if err != nil { return err }
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

// EnsureHardwareLabel (Sanitize & Inject Single Source of Truth)
func EnsureHardwareLabel(hash string) (bool, error) {
	contentBytes, err := os.ReadFile(OssecConfPath)
	if err != nil { return false, err }
	content := string(contentBytes)

	correctLine := fmt.Sprintf(`<label key="%s">%s</label>`, LabelKey, hash)
	
	// Cek apakah sudah sempurna
	reAnyHash := regexp.MustCompile(fmt.Sprintf(`<label key="%s">.*?</label>`, LabelKey))
	matches := reAnyHash.FindAllString(content, -1)
	
	if len(matches) == 1 && matches[0] == correctLine {
		return false, nil
	}

	fmt.Println("[CONFIG] Fixing hardware_hash labels (Removing duplicates/fakes)...")

	// 1. Hapus SEMUA label hardware_hash
	cleanContent := reAnyHash.ReplaceAllString(content, "")

	// 2. Inject SATU yang benar
	var finalContent string
	if strings.Contains(cleanContent, "</labels>") {
		finalContent = strings.Replace(cleanContent, "</labels>", "  "+correctLine+"\n    </labels>", 1)
	} else {
		block := fmt.Sprintf("\n  <labels>\n    %s\n  </labels>\n", correctLine)
		finalContent = strings.Replace(cleanContent, "</ossec_config>", block+"</ossec_config>", 1)
	}

	if err := os.WriteFile(OssecConfPath, []byte(finalContent), 0644); err != nil {
		return false, err
	}
	return true, nil
}

func copyFile(src, dst string) error {
	in, _ := os.Open(src); defer in.Close()
	out, _ := os.Create(dst); defer out.Close()
	_, err := io.Copy(out, in)
	return err
}