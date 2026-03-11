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
