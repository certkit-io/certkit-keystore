package utils

import (
	"net"
	"os/user"
)

// DetectInstallType describes how the keystore was installed and is run:
// "container", "msi", "windows-service", "systemd", or "other" (run by hand,
// or by something else).
func DetectInstallType() string {
	if IsContainerEnvironment() {
		return "container"
	}
	return serviceInstallType()
}

// RunAsUser is the account the keystore runs as, e.g. "root" or
// "NT AUTHORITY\SYSTEM".
func RunAsUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// LocalIPAddresses lists this machine's global unicast addresses, without
// loopback and link-local ones.
func LocalIPAddresses() []string {
	ips := []string{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.IsGlobalUnicast() {
			ips = append(ips, ipNet.IP.String())
		}
	}
	return ips
}
