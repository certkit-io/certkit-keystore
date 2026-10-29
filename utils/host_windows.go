package utils

import (
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
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

// OSVersion describes the Windows edition and build, e.g.
// "Windows Server 2022 Datacenter 21H2 (build 20348.2340)".
func OSVersion() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()

	product, _, err := key.GetStringValue("ProductName")
	if err != nil || product == "" {
		return ""
	}
	build, _, _ := key.GetStringValue("CurrentBuild")

	// Windows 11 kept "Windows 10" as its ProductName; its builds start at 22000.
	if n, err := strconv.Atoi(build); err == nil && n >= 22000 && strings.HasPrefix(product, "Windows 10") {
		product = "Windows 11" + strings.TrimPrefix(product, "Windows 10")
	}

	name := product
	if displayVersion, _, err := key.GetStringValue("DisplayVersion"); err == nil && displayVersion != "" {
		name += " " + displayVersion
	}
	if build != "" {
		if ubr, _, err := key.GetIntegerValue("UBR"); err == nil {
			build += "." + strconv.FormatUint(ubr, 10)
		}
		name += " (build " + build + ")"
	}
	return name
}

func serviceInstallType() string {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return "other"
	}
	if msiProductInstalled() {
		return "msi"
	}
	return "windows-service"
}

var productCodePattern = regexp.MustCompile(`^\{[0-9A-Fa-f\-]+\}$`)

// msiProductInstalled reports whether the keystore MSI is installed. Like
// Test-MsiProductInstalled in scripts/install.ps1, it looks for the GUID-named
// uninstall key an MSI registers; script installs never register one.
func msiProductInstalled() bool {
	for _, path := range []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	} {
		root, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		names, err := root.ReadSubKeyNames(-1)
		root.Close()
		if err != nil {
			continue
		}
		for _, name := range names {
			if !productCodePattern.MatchString(name) {
				continue
			}
			product, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+name, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			displayName, _, _ := product.GetStringValue("DisplayName")
			product.Close()
			if displayName == "CertKit Keystore" {
				return true
			}
		}
	}
	return false
}
