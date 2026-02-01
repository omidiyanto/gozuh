package service

import (
	"fmt"
	"gozuh/internal/config"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func SetupServiceLogging() {
	config.EnsureDir(config.ServiceLogFile)
	rotateLogs()
	f, err := os.OpenFile(config.ServiceLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	log.SetOutput(f)
	log.SetPrefix("[SERVICE] ")
	log.SetFlags(log.LstdFlags)
}

func rotateLogs() {
	info, err := os.Stat(config.ServiceLogFile)
	if err == nil && info.Size() > 0 {
		timestamp := time.Now().Format("2006-01-02_15-04-05")
		newName := fmt.Sprintf("%s.%s.old", config.ServiceLogFile, timestamp)
		os.Rename(config.ServiceLogFile, newName)
	}
	cleanOldLogs()
}

func cleanOldLogs() {
	dir := filepath.Dir(config.ServiceLogFile)
	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var logFiles []string
	baseName := filepath.Base(config.ServiceLogFile)
	for _, file := range files {
		if strings.HasPrefix(file.Name(), baseName+".") && strings.HasSuffix(file.Name(), ".old") {
			logFiles = append(logFiles, filepath.Join(dir, file.Name()))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(logFiles)))
	if len(logFiles) > 3 {
		for _, f := range logFiles[3:] {
			os.Remove(f)
		}
	}
}
func DisableFileLogging() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("[CLI] ")
	log.SetFlags(log.Ltime)
}