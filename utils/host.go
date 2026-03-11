package utils

import (
	"os"
	"runtime"
	"strings"
)

func DetectHostType() string {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "k8s"
	}

	if isDockerEnvironment() {
		return "docker"
	}

	if isVirtualMachineEnvironment() {
		return "VM"
	}

	return "Bare metal"
}

func isDockerEnvironment() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
			content := strings.ToLower(string(data))
			if strings.Contains(content, "docker") ||
				strings.Contains(content, "containerd") ||
				strings.Contains(content, "kubepods") {
				return true
			}
		}
	}

	return false
}

func LooksVirtualized(s string) bool {
	lower := strings.ToLower(s)
	indicators := []string{
		"vmware",
		"virtualbox",
		"kvm",
		"qemu",
		"microsoft corporation",
		"hyper-v",
		"xen",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}
