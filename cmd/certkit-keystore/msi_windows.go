//go:build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreInstall "github.com/certkit-io/certkit-keystore/install"
)

// bootstrapConfigCmd creates the initial config for MSI-based installs and
// opens the firewall. Unlike installCmd it never prompts and never touches the
// SCM or the event log source (the MSI does both). It runs as a deferred
// custom action, so every value arrives via flags built from MSI properties:
// deferred actions do not inherit the installing user's environment.
func bootstrapConfigCmd(args []string) {
	fs := flag.NewFlagSet("bootstrap-config", flag.ExitOnError)
	configPath := fs.String("config", keystoreInstall.DefaultConfigPath, "path to config file")
	key := fs.String("key", "", "registration key, required when no config exists")
	host := fs.String("host", "", "keystore hostname or IP, required when no config exists")
	port := fs.String("port", config.DefaultKeystorePort, "keystore listen port")
	storageDir := fs.String("storage-dir", keystoreInstall.DefaultStorageDir, "directory for key storage")
	fs.Parse(args)

	if !filepath.IsAbs(*configPath) {
		log.Fatalf("--config must be an absolute path: %s", *configPath)
	}

	if err := ensureMsiConfig(*configPath, *key, *host, *port, *storageDir); err != nil {
		log.Fatalf("bootstrap-config failed: %v", err)
	}

	keystoreInstall.OpenFirewallForConfig(*configPath)
}

// ensureMsiConfig applies installCmd's rules without prompting: an initialized
// config is always kept (upgrades, migrations), and an uninitialized one is
// kept unless a registration key is supplied, which replaces it (e.g. to fix a
// mistyped key before the keystore ever registered).
func ensureMsiConfig(configPath, key, host, port, storageDir string) error {
	key = strings.TrimSpace(key)
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)

	existing, err := config.ReadConfig(configPath)
	if err == nil && existing.Keystore != nil && existing.Keystore.Initialized {
		log.Printf("Config at %s is already initialized, keeping it", configPath)
		return nil
	}
	if err == nil && key == "" {
		log.Printf("Config already exists at %s, keeping it", configPath)
		return nil
	}

	if key == "" || host == "" {
		return fmt.Errorf("REGISTRATIONKEY and HOST are required when there is no usable config at %s", configPath)
	}
	if _, _, err := config.ParseRegistrationKey(key); err != nil {
		return err
	}
	if err := validatePort(port); err != nil {
		return fmt.Errorf("invalid PORT: %w", err)
	}
	// Package.wxs passes the directory with a trailing "\." (see the comment
	// there); Clean removes it.
	storageDir = filepath.Clean(strings.TrimSpace(storageDir))
	if _, err := validateStorageDir(storageDir); err != nil {
		return fmt.Errorf("invalid STORAGEDIR: %w", err)
	}

	// Interactive installs ask the user to confirm these; here they are only
	// logged, as the value may be correct (e.g. a load balancer name).
	if err := validateHost(host); err != nil {
		log.Printf("Warning: %v", err)
	}
	if err := checkPortInUse(host, port); err != nil {
		log.Printf("Warning: %v", err)
	}

	if err := config.CreateInitialConfig(configPath, key, host, port, storageDir, keystoreInstall.ServiceName); err != nil {
		return err
	}
	log.Printf("Config written to %s", configPath)
	return nil
}

// msiCleanupCmd is the uninstall-time counterpart, run as a deferred custom
// action after StopServices on a true uninstall (never on upgrade). The MSI
// removes the service, event source, and files itself; like the uninstall
// command, this removes the firewall rule and the config and keeps stored
// certificates. Everything is best effort — a cleanup problem must never
// block or roll back an uninstall, so this always exits 0.
func msiCleanupCmd(args []string) {
	fs := flag.NewFlagSet("msi-cleanup", flag.ExitOnError)
	configPath := fs.String("config", keystoreInstall.DefaultConfigPath, "path to config file")
	fs.Parse(args)

	keystoreInstall.CloseFirewallForConfig(*configPath)

	if err := os.Remove(*configPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to remove config file %s: %v", *configPath, err)
	} else if err == nil {
		log.Printf("Removed config file %s", *configPath)
	}
}
