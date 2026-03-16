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

type Config struct {
	CertkitBaseUrl string        `json:"certkit_base_url"`
	Keystore       *KeystoreInfo `json:"keystore"`
	Auth           *AuthCreds    `json:"auth,omitempty"`
}

type KeystoreInfo struct {
	Id            string `json:"id"`
	ApplicationId string `json:"application_id"`
	Host          string `json:"host"`
	Port          string `json:"port"`
	StorageDir    string `json:"storage_dir"`
	Initialized   bool   `json:"initialized"`
}

func (k *KeystoreInfo) BaseUrl() string {
	if k.Port == "443" {
		return "https://" + k.Host
	}
	return "https://" + k.Host + ":" + k.Port
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

const DefaultCertkitBaseUrl = "https://localhost:44301" //"https://app.certkit.io/"
const DefaultKeystorePort = "443"
const DefaultStorageDir = "./"

func ParseRegistrationKey(key string) (applicationId string, keystoreId string, err error) {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid registration key format: expected {app_id}.{keystore_id}")
	}
	return parts[0], parts[1], nil
}

func CreateInitialConfig(configPath string, registrationKey string, host string, port string, storageDir string) error {
	if registrationKey == "" {
		registrationKey = os.Getenv("CERTKIT_REGISTRATION_KEY")
	}
	if registrationKey == "" {
		return fmt.Errorf("registration key is required: pass --key or set CERTKIT_REGISTRATION_KEY")
	}
	if host == "" {
		return fmt.Errorf("host is required: pass --host (e.g. --host keystore.example.com or --host 192.168.1.50)")
	}

	applicationId, keystoreId, err := ParseRegistrationKey(registrationKey)
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
		CertkitBaseUrl: certkitBaseUrl,
		Keystore: &KeystoreInfo{
			Id:            keystoreId,
			ApplicationId: applicationId,
			Host:          host,
			Port:          port,
			StorageDir:    storageDir,
			Initialized:   false,
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

func LoadConfig(path string) (*Config, error) {
	cfg, err := ReadConfig(path)
	if err != nil {
		return nil, err
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

func SaveConfig(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
