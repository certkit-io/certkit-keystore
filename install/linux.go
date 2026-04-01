//go:build !windows

package install

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	DefaultConfigPath = "/etc/certkit-keystore/config.json"
	DefaultStorageDir = "/etc/certkit-keystore/certificates"
	DefaultUnitPath   = "/etc/systemd/system"
)

func InstallService(configPath string) {
	mustBeRoot()

	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("failed to determine executable path: %v", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		log.Fatalf("failed to resolve executable symlinks: %v", err)
	}

	if _, err := os.Stat(exe); err != nil {
		log.Fatalf("binary path does not exist: %s (%v)", exe, err)
	}
	if !strings.HasPrefix(configPath, "/") {
		log.Fatalf("config path must be an absolute path: %s", configPath)
	}

	if _, err := exec.LookPath("systemctl"); err != nil {
		log.Printf("systemd not detected; skipping unit install. Run manually: %s run --config %s", exe, configPath)
		return
	}

	unitPath := filepath.Join(DefaultUnitPath, ServiceName+".service")
	unitContent := renderSystemdUnit(exe, configPath)

	if err := os.WriteFile(unitPath, []byte(unitContent), 0o644); err != nil {
		log.Fatalf("failed to write unit file %s: %v", unitPath, err)
	}

	if err := runCmdLogged("systemctl", "daemon-reload"); err != nil {
		log.Fatalf("systemctl daemon-reload failed: %v", err)
	}
	if err := runCmdLogged("systemctl", "enable", "--now", ServiceName+".service"); err != nil {
		log.Fatalf("systemctl enable --now failed: %v", err)
	}

	log.Printf("Installed and started %s (unit: %s)", ServiceName, unitPath)
	log.Printf("   systemctl status %s.service", ServiceName)
}

func renderSystemdUnit(exePath, configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=CertKit Keystore
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run --config %s
Restart=always
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
`, shellEscape(exePath), shellEscape(configPath))
}

func shellEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func mustBeRoot() {
	if os.Geteuid() != 0 {
		log.Fatal("this command must be run as root (try: sudo ...)")
	}
}

func UninstallService() {
	mustBeRoot()

	unitName := ServiceName + ".service"
	unitPath := filepath.Join(DefaultUnitPath, unitName)

	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		log.Printf("Service %s is not installed; nothing to remove", ServiceName)
		return
	}

	if _, err := exec.LookPath("systemctl"); err == nil {
		if err := runCmdLogged("systemctl", "stop", unitName); err != nil {
			log.Printf("systemctl stop failed for %s: %v", unitName, err)
		}
		if err := runCmdLogged("systemctl", "disable", unitName); err != nil {
			log.Printf("systemctl disable failed for %s: %v", unitName, err)
		}
	}

	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("failed to remove unit file %s: %v", unitPath, err)
	}

	if _, err := exec.LookPath("systemctl"); err == nil {
		if err := runCmdLogged("systemctl", "daemon-reload"); err != nil {
			log.Printf("systemctl daemon-reload failed: %v", err)
		}
		if err := runCmdLogged("systemctl", "reset-failed", unitName); err != nil {
			log.Printf("systemctl reset-failed failed for %s: %v", unitName, err)
		}
	}

	log.Printf("Service %s has been removed", ServiceName)
}

func runCmdLogged(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if out.Len() > 0 {
		log.Printf("Ran command: %s %s:\n%s", name, strings.Join(args, " "), strings.TrimSpace(out.String()))
	}
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}
