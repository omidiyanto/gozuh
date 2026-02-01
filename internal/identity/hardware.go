package identity

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/yusufpapurcu/wmi"
)

type HardwareInfo struct {
	UUID    string
	Serial  string
	MACList []string
	MACHash string
	Hash    string
}

type Win32_ComputerSystemProduct struct {
	UUID string
}

type Win32_BIOS struct {
	SerialNumber string
}

type Win32_NetworkAdapter struct {
	MACAddress      string
	PNPDeviceID     string
	Description     string
	AdapterType     string
	PhysicalAdapter bool
}

func GetIdentity(allowVirtual bool) (*HardwareInfo, error) {
	var uuid, serial string

	var csp []Win32_ComputerSystemProduct
	if err := wmi.Query(wmi.CreateQuery(&csp, ""), &csp); err == nil && len(csp) > 0 {
		uuid = strings.TrimSpace(csp[0].UUID)
	}

	var bios []Win32_BIOS
	if err := wmi.Query(wmi.CreateQuery(&bios, ""), &bios); err == nil && len(bios) > 0 {
		serial = strings.TrimSpace(bios[0].SerialNumber)
	}

	macList, macString := getRobustMAC(allowVirtual)
	
	macHashBytes := sha256.Sum256([]byte(macString))
	macHash := fmt.Sprintf("%x", macHashBytes)

	rawString := fmt.Sprintf("%s-%s-%s", uuid, serial, macString)
	hashBytes := sha256.Sum256([]byte(rawString))

	return &HardwareInfo{
		UUID:    uuid,
		Serial:  serial,
		MACList: macList,
		MACHash: macHash,
		Hash:    fmt.Sprintf("%x", hashBytes),
	}, nil
}

func getRobustMAC(allowVirtual bool) ([]string, string) {
	var adapters []Win32_NetworkAdapter
	query := "SELECT MACAddress, PNPDeviceID, Description, AdapterType, PhysicalAdapter FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL"
	if err := wmi.Query(query, &adapters); err != nil {
		return []string{"ERROR"}, "00:00:00:00:00:00"
	}

	var validMACs []string

	for _, adapter := range adapters {
		pnp := strings.ToUpper(adapter.PNPDeviceID)
		desc := strings.ToUpper(adapter.Description)
		if strings.HasPrefix(pnp, "USB\\") { continue } 
		if strings.Contains(desc, "VPN") { continue }
		if strings.Contains(desc, "LOOPBACK") { continue }
		if strings.Contains(desc, "WI-FI DIRECT") { continue }
		if !allowVirtual {
			if !adapter.PhysicalAdapter {
				continue
			}
			if strings.Contains(desc, "VIRTUAL") || 
			   strings.Contains(desc, "HYPER-V") || 
			   strings.Contains(desc, "VMWARE") ||       
			   strings.Contains(desc, "VIRTUALBOX") ||   
			   strings.Contains(desc, "MULTIPLEXOR") ||  
			   strings.Contains(desc, "TAP-WINDOWS") {  
				continue
			}
		}
		if allowVirtual {
			if strings.Contains(desc, "DEFAULT SWITCH") { continue }
		}
		mac := strings.ToUpper(strings.TrimSpace(adapter.MACAddress))
		if mac != "" {
			validMACs = append(validMACs, mac)
		}
	}

	if len(validMACs) == 0 {
		return []string{"NO_VALID_NIC"}, "00:00:00:00:00:00"
	}

	sort.Strings(validMACs)
	combined := strings.Join(validMACs, "|")
	return validMACs, combined
}