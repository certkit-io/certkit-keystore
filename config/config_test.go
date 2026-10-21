package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
)

func keepCurrentConfig(t *testing.T) {
	t.Helper()
	prevConfig, prevPath := CurrentConfig, CurrentPath
	t.Cleanup(func() {
		CurrentConfig = prevConfig
		CurrentPath = prevPath
	})
}

// writeV1Config writes a config as keystores before v2 did: no version, and
// the collection the keystore served in application_id.
func writeV1Config(t *testing.T, initialized bool) (path string, keyPair *keystoreCrypto.KeyPair) {
	t.Helper()
	keyPair, err := keystoreCrypto.CreateNewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(map[string]any{
		"certkit_base_url": "https://app.certkit.io/",
		"keystore": map[string]any{
			"id":             "ks01",
			"application_id": "x7k2",
			"host":           "keystore.example.com",
			"port":           "443",
			"storage_dir":    "/etc/certkit-keystore/certificates",
			"service_name":   "certkit-keystore",
			"initialized":    initialized,
		},
		"auth": map[string]any{"key_pair": keyPair},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, keyPair
}

func TestLoadConfigUpgradesVersion1(t *testing.T) {
	keepCurrentConfig(t)
	path, keyPair := writeV1Config(t, true)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Version != ConfigVersion {
		t.Errorf("Version = %d, want %d", cfg.Version, ConfigVersion)
	}
	if cfg.Keystore.Id != "ks01" || cfg.Keystore.Host != "keystore.example.com" || !cfg.Keystore.Initialized {
		t.Errorf("keystore settings were not kept: %+v", cfg.Keystore)
	}
	if cfg.Keystore.AccountId != "" {
		t.Errorf("AccountId = %q, want empty for a registered keystore", cfg.Keystore.AccountId)
	}
	if cfg.Auth.KeyPair.PrivateKey != keyPair.PrivateKey {
		t.Error("the signing key changed")
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(saved), "application_id") {
		t.Errorf("upgraded config still has application_id:\n%s", saved)
	}
	if !strings.Contains(string(saved), `"version": 2`) {
		t.Errorf("upgraded config has no version:\n%s", saved)
	}

	// Loading the upgraded config changes nothing.
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("second LoadConfig: %v", err)
	}
	if again, _ := os.ReadFile(path); string(again) != string(saved) {
		t.Error("an up-to-date config was rewritten")
	}
}

func TestLoadConfigUpgradesUnregisteredVersion1(t *testing.T) {
	keepCurrentConfig(t)
	path, _ := writeV1Config(t, false)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	// It still has to register, with the key it was installed with.
	if got := cfg.Keystore.RegistrationKey(); got != "x7k2.ks01" {
		t.Errorf("RegistrationKey = %q, want x7k2.ks01", got)
	}
}

func TestCreateInitialConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := CreateInitialConfig(path, "acct.ks01", "keystore.example.com", "", "", "certkit-keystore"); err != nil {
		t.Fatal(err)
	}

	cfg, err := ReadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != ConfigVersion || cfg.Keystore.AccountId != "acct" || cfg.Keystore.Id != "ks01" || cfg.Keystore.Port != DefaultKeystorePort {
		t.Errorf("unexpected config: version %d, keystore %+v", cfg.Version, cfg.Keystore)
	}
	if cfg.Keystore.RegistrationKey() != "acct.ks01" {
		t.Errorf("RegistrationKey = %q, want acct.ks01", cfg.Keystore.RegistrationKey())
	}
}

func TestSaveConfigReplacesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	for _, host := range []string{"first.example.com", "second.example.com"} {
		cfg := &Config{Version: ConfigVersion, Keystore: &KeystoreInfo{Id: "ks01", Host: host}}
		if err := SaveConfig(cfg, path); err != nil {
			t.Fatalf("SaveConfig: %v", err)
		}
		got, err := ReadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if got.Keystore.Host != host {
			t.Errorf("host = %q, want %q", got.Keystore.Host, host)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory has %v, want only config.json", names)
	}
}

func TestParseRegistrationKey(t *testing.T) {
	account, keystore, err := ParseRegistrationKey("acct.ks01")
	if err != nil || account != "acct" || keystore != "ks01" {
		t.Errorf("ParseRegistrationKey = %q, %q, %v", account, keystore, err)
	}
	for _, bad := range []string{"", "nodot", ".ks01", "acct."} {
		if _, _, err := ParseRegistrationKey(bad); err == nil {
			t.Errorf("ParseRegistrationKey(%q) succeeded, want an error", bad)
		}
	}
}
