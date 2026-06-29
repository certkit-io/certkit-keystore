package install

import (
	"fmt"
	"log"
	"strconv"

	"github.com/certkit-io/certkit-keystore/config"
)

// validateFirewallPort ensures the port is a numeric value within the valid TCP
// port range before it is used in (or interpolated into) a firewall command.
// The install flow already validates the port, but the config file could be
// hand-edited, so the firewall layer revalidates as defense-in-depth.
func validateFirewallPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port %q: not a number", port)
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %d: out of range (1-65535)", n)
	}
	return nil
}

// openFirewallForConfig reads the listen port from the config file and opens it
// in the host firewall so CertKit agents can reach the keystore. Any failure is
// logged as a warning and never aborts the install (the service is already up;
// an admin can open the port by hand).
func openFirewallForConfig(configPath string) {
	cfg, err := config.ReadConfig(configPath)
	if err != nil {
		log.Printf("Warning: could not read config to open firewall: %v", err)
		return
	}
	if cfg.Keystore == nil || cfg.Keystore.Port == "" {
		log.Printf("Warning: no port configured; skipping firewall rule")
		return
	}
	if err := openFirewallPort(cfg.Keystore.Port); err != nil {
		log.Printf("Warning: could not open firewall for port %s: %v", cfg.Keystore.Port, err)
	}
}

// closeFirewallForConfig removes the firewall rule that openFirewallForConfig
// added. The port is read from config when available (Linux needs it to delete
// the matching rule); Windows removes by rule name and ignores it. Failures are
// logged as warnings and never abort the uninstall.
func closeFirewallForConfig(configPath string) {
	port := ""
	if cfg, err := config.ReadConfig(configPath); err == nil && cfg.Keystore != nil {
		port = cfg.Keystore.Port
	}
	if err := closeFirewallPort(port); err != nil {
		log.Printf("Warning: could not remove firewall rule: %v", err)
	}
}
