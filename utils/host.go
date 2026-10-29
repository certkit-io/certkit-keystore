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

// IsContainerEnvironment reports whether the process is running inside a
// container (Docker, Kubernetes, etc.), where the image, not the process,
// owns the binary.
func IsContainerEnvironment() bool {
	return os.Getenv("KUBERNETES_SERVICE_HOST") != "" || isDockerEnvironment()
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
