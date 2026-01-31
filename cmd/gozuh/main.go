package main

import (
	"flag"
	"fmt"
	"gozuh/internal/service"
	"golang.org/x/sys/windows/svc"
)

func main() {
	isService, _ := svc.IsWindowsService()
	if isService {
		runService()
		return
	}

	install := flag.Bool("install", false, "Smart Installation (Recovery/Fresh)")
	uninstall := flag.Bool("uninstall", false, "Local Uninstall (Keep Server Data)")
	purge := flag.Bool("purge", false, "Full Decommission (Local + Server Delete)")
	debug := flag.Bool("debug", false, "Run Diagnostics & Pre-flight Check")
	flag.Parse()

	if *debug {
		service.RunDebug()
		return
	}

	if *purge {
		service.RunPurge()
		return
	}

	if *install {
		service.RunInstall()
		return
	} 
	
	if *uninstall {
		service.RunUninstall()
	} else {
		printBanner()
	}
}

func runService() {
	svc.Run("GOZUH", &service.GozuhService{})
}

func printBanner() {
	fmt.Println("GOZUH - Wazuh Agent Companion")
	fmt.Println("----------------------------------")
	fmt.Println("Flags:")
	fmt.Println("  --install   : Smart Install & Register (Bootstrap)")
	fmt.Println("  --uninstall : Local Uninstall only")
	fmt.Println("  --purge     : Full Decommission (Delete on Server & Local)")
	fmt.Println("  --debug     : Show Identity & Server Connection Status")
}