package identity

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/yusufpapurcu/wmi"
)

type HardwareInfo struct {
	UUID   string
	Serial string
	MAC    string
	Hash   string
}

type Win32_ComputerSystemProduct struct {
	UUID string
}

type Win32_BIOS struct {
	SerialNumber string
}

func GetIdentity() (*HardwareInfo, error) {
	var uuid, serial string

	// 1. Ambil UUID via WMI
	var csp []Win32_ComputerSystemProduct
	if err := wmi.Query(wmi.CreateQuery(&csp, ""), &csp); err == nil && len(csp) > 0 {
		uuid = strings.TrimSpace(csp[0].UUID)
	}

	// 2. Ambil Serial BIOS
	var bios []Win32_BIOS
	if err := wmi.Query(wmi.CreateQuery(&bios, ""), &bios); err == nil && len(bios) > 0 {
		serial = strings.TrimSpace(bios[0].SerialNumber)
	}

	// 3. Ambil MAC Tercepat
	mac, _ := getPrimaryMAC()

	// 4. Generate Hash
	rawString := fmt.Sprintf("%s-%s-%s", uuid, serial, mac)
	hashBytes := sha256.Sum256([]byte(rawString))

	return &HardwareInfo{
		UUID:   uuid,
		Serial: serial,
		MAC:    mac,
		Hash:   fmt.Sprintf("%x", hashBytes),
	}, nil
}

func getPrimaryMAC() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil { return "", err }
	var macs []string
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 { continue }
		if len(i.HardwareAddr) > 0 { macs = append(macs, i.HardwareAddr.String()) }
	}
	if len(macs) == 0 { return "00:00:00:00:00:00", nil }
	sort.Strings(macs)
	return macs[0], nil
}