package utils

import (
	"os"
	"strings"
)

func isVirtualMachineEnvironment() bool {
	// Check DMI product name
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		if LooksVirtualized(string(data)) {
			return true
		}
	}

	// Check DMI system vendor
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		if LooksVirtualized(string(data)) {
			return true
		}
	}

	// Check /proc/cpuinfo for hypervisor flag
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "flags") && strings.Contains(line, "hypervisor") {
				return true
			}
		}
	}

	return false
}

// OSVersion describes the Linux distribution and kernel, e.g.
// "Ubuntu 22.04.4 LTS (kernel 5.15.0-91-generic)".
func OSVersion() string {
	name := osReleasePrettyName()
	kernel := ""
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(data))
	}

	switch {
	case name != "" && kernel != "":
		return name + " (kernel " + kernel + ")"
	case kernel != "":
		return "Linux (kernel " + kernel + ")"
	default:
		return name
	}
}

func osReleasePrettyName() string {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line), "PRETTY_NAME="); ok {
				return strings.Trim(value, `"'`)
			}
		}
	}
	return ""
}

func serviceInstallType() string {
	// systemd sets INVOCATION_ID for every unit it starts.
	if os.Getenv("INVOCATION_ID") != "" {
		return "systemd"
	}
	return "other"
}
