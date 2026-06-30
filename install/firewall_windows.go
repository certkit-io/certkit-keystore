//go:build windows

package install

import (
	"fmt"

	"github.com/certkit-io/certkit-keystore/utils"
)

// firewallRuleDisplayName is the stable name of the Windows Firewall rule. Using
// a fixed name lets us remove the rule on uninstall without knowing the port,
// and makes re-installs idempotent (we remove-then-add).
const firewallRuleDisplayName = "CertKit Keystore"

// openFirewallPort opens the given inbound TCP port in Windows Firewall so
// CertKit agents can reach the keystore. Any rule with the same display name is
// removed first, so re-installs (including a changed port) stay idempotent.
func openFirewallPort(port string) error {
	if err := validateFirewallPort(port); err != nil {
		return err
	}

	script := fmt.Sprintf(
		"Remove-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue; "+
			"New-NetFirewallRule -DisplayName '%s' -Direction Inbound -Action Allow -Protocol TCP -LocalPort %s | Out-Null",
		firewallRuleDisplayName, firewallRuleDisplayName, port,
	)
	return utils.RunPowerShellLogged(script)
}

// closeFirewallPort removes the rule added by openFirewallPort. The rule is
// removed by display name, so the port argument is unused on Windows.
func closeFirewallPort(_ string) error {
	script := fmt.Sprintf(
		"Remove-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue",
		firewallRuleDisplayName,
	)
	return utils.RunPowerShellLogged(script)
}
