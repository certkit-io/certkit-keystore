//go:build !windows

package install

import (
	"log"
	"os/exec"
	"strings"
)

// openFirewallPort opens the given inbound TCP port in the host firewall so
// CertKit agents can reach the keystore. ufw is preferred; firewalld is used as
// a fallback. If neither is active we log the manual commands and return nil so
// the install is not blocked.
func openFirewallPort(port string) error {
	if err := validateFirewallPort(port); err != nil {
		return err
	}

	switch {
	case ufwActive():
		// `ufw allow` is idempotent, so re-running install will not create duplicates.
		return runCmdLogged("ufw", "allow", port+"/tcp")
	case firewalldActive():
		return addFirewalldPort(port)
	default:
		log.Printf("Warning: no active ufw or firewalld detected; if a firewall is in use, open the port manually, e.g.: ufw allow %s/tcp  OR  firewall-cmd --permanent --add-port=%s/tcp && firewall-cmd --reload", port, port)
		return nil
	}
}

// closeFirewallPort removes the rule added by openFirewallPort.
func closeFirewallPort(port string) error {
	if err := validateFirewallPort(port); err != nil {
		return err
	}

	switch {
	case ufwActive():
		return runCmdLogged("ufw", "delete", "allow", port+"/tcp")
	case firewalldActive():
		return removeFirewalldPort(port)
	default:
		log.Printf("Warning: no active ufw or firewalld detected; if a firewall is in use, remove the port manually, e.g.: ufw delete allow %s/tcp  OR  firewall-cmd --permanent --remove-port=%s/tcp && firewall-cmd --reload", port, port)
		return nil
	}
}

// ufwActive reports whether ufw is installed and reporting an active status.
func ufwActive() bool {
	if _, err := exec.LookPath("ufw"); err != nil {
		return false
	}
	out, err := exec.Command("ufw", "status").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Status: active")
}

// firewalldActive reports whether firewalld is installed and running.
func firewalldActive() bool {
	if _, err := exec.LookPath("firewall-cmd"); err != nil {
		return false
	}
	// `firewall-cmd --state` prints "running" and exits 0 when active; otherwise
	// it exits non-zero (Output returns an error), so a clean run means running.
	out, err := exec.Command("firewall-cmd", "--state").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "running"
}

// addFirewalldPort opens the port in firewalld's default zone. The change is
// made permanent and then applied with --reload. `--permanent --add-port` is
// idempotent, so re-running install is safe.
func addFirewalldPort(port string) error {
	if err := runCmdLogged("firewall-cmd", "--permanent", "--add-port="+port+"/tcp"); err != nil {
		return err
	}
	return runCmdLogged("firewall-cmd", "--reload")
}

// removeFirewalldPort removes the port from firewalld's default zone and reloads.
func removeFirewalldPort(port string) error {
	if err := runCmdLogged("firewall-cmd", "--permanent", "--remove-port="+port+"/tcp"); err != nil {
		return err
	}
	return runCmdLogged("firewall-cmd", "--reload")
}
