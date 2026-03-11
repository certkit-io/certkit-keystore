package utils

import (
	"os/exec"
	"strings"
)

func isVirtualMachineEnvironment() bool {
	// Try PowerShell: query Win32_ComputerSystem for HypervisorPresent and Manufacturer/Model
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_ComputerSystem | Select-Object -Property HypervisorPresent,Manufacturer,Model | Format-List",
	).Output()
	if err == nil {
		output := string(out)
		if strings.Contains(output, "HypervisorPresent : True") {
			return true
		}
		if LooksVirtualized(output) {
			return true
		}
	}

	// Fallback: wmic
	out, err = exec.Command("wmic", "computersystem", "get", "manufacturer,model").Output()
	if err == nil {
		if LooksVirtualized(string(out)) {
			return true
		}
	}

	return false
}
