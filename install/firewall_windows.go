//go:build windows

package install

// firewallRuleDisplayName is the stable name of the Windows Firewall rule. Using
// a fixed name lets us remove the rule on uninstall without knowing the port,
// and makes re-installs idempotent (we remove-then-add).
const firewallRuleDisplayName = "CertKit Keystore"

// The rule is managed with netsh rather than PowerShell: this also runs from
// the MSI's custom actions, and AV heuristics flag installer-spawned
// PowerShell. netsh's name= matches the rule's display name, so rules created
// by earlier (New-NetFirewallRule) installs are replaced as well.

// openFirewallPort opens the given inbound TCP port in Windows Firewall so
// CertKit agents can reach the keystore. Any rule with the same display name is
// removed first, so re-installs (including a changed port) stay idempotent.
func openFirewallPort(port string) error {
	if err := validateFirewallPort(port); err != nil {
		return err
	}

	// netsh exits non-zero when no rule matches, which is the common case here.
	_ = deleteFirewallRule()
	return runCmdLogged("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+firewallRuleDisplayName,
		"dir=in",
		"action=allow",
		"protocol=TCP",
		"localport="+port,
	)
}

// closeFirewallPort removes the rule added by openFirewallPort. The rule is
// removed by display name, so the port argument is unused on Windows.
func closeFirewallPort(_ string) error {
	return deleteFirewallRule()
}

func deleteFirewallRule() error {
	return runCmdLogged("netsh", "advfirewall", "firewall", "delete", "rule", "name="+firewallRuleDisplayName)
}
