package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
)

var CurrentConfig Config
var CurrentPath string
var CurrentVersion VersionInfo

// ConfigVersion is the config format this keystore writes. Version 1 configs
// (no version field) belonged to a single collection; from version 2 a
// keystore serves whichever collections CertKit assigns to it.
const ConfigVersion = 2

type Config struct {
	Version        int           `json:"version"`
	CertkitBaseUrl string        `json:"certkit_base_url"`
	Keystore       *KeystoreInfo `json:"keystore"`
	Auth           *AuthCreds    `json:"auth,omitempty"`
}

type KeystoreInfo struct {
	Id string `json:"id"`
	// AccountId is the first half of the registration key. It is only needed
	// to register, so configs upgraded from version 1 may not have it.
	AccountId   string `json:"account_id,omitempty"`
	Host        string `json:"host"`
	Port        string `json:"port"`
	StorageDir  string `json:"storage_dir"`
	ServiceName string `json:"service_name"`
	Initialized bool   `json:"initialized"`

	// LegacyApplicationId is read from version 1 configs only, and never
	// written back.
	LegacyApplicationId string `json:"application_id,omitempty"`
}

func (k *KeystoreInfo) BaseUrl() string {
	if k.Port == "443" {
		return "https://" + k.Host
	}
	return "https://" + k.Host + ":" + k.Port
}

// RegistrationKey is the key the keystore was installed with.
func (k *KeystoreInfo) RegistrationKey() string {
	return k.AccountId + "." + k.Id
}

type AuthCreds struct {
	KeyPair *keystoreCrypto.KeyPair `json:"key_pair"`
}

type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

func hasKeyPair(cfg *Config) bool {
	return cfg.Auth != nil &&
		cfg.Auth.KeyPair != nil &&
		cfg.Auth.KeyPair.PublicKey != "" &&
		cfg.Auth.KeyPair.PrivateKey != ""
}

const DefaultCertkitBaseUrl = "https://app.certkit.io/"
const DefaultKeystorePort = "443"
const DefaultStorageDir = "./certificates"

func ParseRegistrationKey(key string) (accountId string, keystoreId string, err error) {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid registration key format: expected {account_id}.{keystore_id}")
	}
	return parts[0], parts[1], nil
}

func CreateInitialConfig(configPath string, registrationKey string, host string, port string, storageDir string, serviceName string) error {
	if registrationKey == "" {
		registrationKey = os.Getenv("CERTKIT_REGISTRATION_KEY")
	}
	if registrationKey == "" {
		return fmt.Errorf("registration key is required: pass --key or set CERTKIT_REGISTRATION_KEY")
	}
	if host == "" {
		return fmt.Errorf("host is required: pass --host (e.g. --host keystore.example.com or --host 192.168.1.50)")
	}

	accountId, keystoreId, err := ParseRegistrationKey(registrationKey)
	if err != nil {
		return err
	}

	if port == "" {
		port = DefaultKeystorePort
	}
	if storageDir == "" {
		storageDir = DefaultStorageDir
	}

	certkitBaseUrl := os.Getenv("CERTKIT_API_BASE")
	if certkitBaseUrl == "" {
		certkitBaseUrl = DefaultCertkitBaseUrl
	}

	cfg := Config{
		Version:        ConfigVersion,
		CertkitBaseUrl: certkitBaseUrl,
		Keystore: &KeystoreInfo{
			Id:          keystoreId,
			AccountId:   accountId,
			Host:        host,
			Port:        port,
			StorageDir:  storageDir,
			ServiceName: serviceName,
			Initialized: false,
		},
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return SaveConfig(&cfg, configPath)
}

func ReadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("config file is empty: %s", path)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// upgradeConfig converts a version 1 config, which named the single
// collection the keystore served, to the current version. It reports whether
// anything changed.
func upgradeConfig(cfg *Config) bool {
	if cfg.Version >= ConfigVersion {
		return false
	}
	if cfg.Keystore != nil {
		// A version 1 keystore that never registered still needs its
		// registration key, whose first half was the collection ID. CertKit
		// accepts either form.
		if !cfg.Keystore.Initialized && cfg.Keystore.AccountId == "" {
			cfg.Keystore.AccountId = cfg.Keystore.LegacyApplicationId
		}
		cfg.Keystore.LegacyApplicationId = ""
	}
	cfg.Version = ConfigVersion
	return true
}

func LoadConfig(path string) (*Config, error) {
	cfg, err := ReadConfig(path)
	if err != nil {
		return nil, err
	}

	if upgradeConfig(cfg) {
		if err := SaveConfig(cfg, path); err != nil {
			return nil, fmt.Errorf("failed to save upgraded config: %w", err)
		}
		log.Printf("Upgraded config at %s to version %d", path, ConfigVersion)
	}

	if !hasKeyPair(cfg) {
		log.Println("No keypair found in config, generating new ed25519 keypair...")
		keyPair, err := keystoreCrypto.CreateNewKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate keypair: %w", err)
		}
		cfg.Auth = &AuthCreds{KeyPair: keyPair}

		if err := SaveConfig(cfg, path); err != nil {
			return nil, fmt.Errorf("failed to save config after keypair generation: %w", err)
		}
		log.Println("Keypair generated and saved to config")
	}

	CurrentConfig = *cfg
	CurrentPath = path

	return cfg, nil
}

// SaveConfig replaces the config file (mode 0600). The config holds the
// keystore's signing key, so it is written to a temp file in the same
// directory, flushed, and renamed over the old one: a crash leaves either the
// old or the new config, never a partial one.
func SaveConfig(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp config file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write config file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync config file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close config file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to replace config file: %w", err)
	}
	tmpName = ""
	return nil
}
