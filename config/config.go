package config

import (
	"encoding/json"
	"fmt"
	"os"
)

var CurrentConfig Config
var CurrentPath string

type Config struct {
	CertkitBaseUrl  string `json:"certkit_base_url"`
	KeystoreBaseUrl string `json:"keystore_base_url"`
	KeystorePort    string `json:"keystore_port"`
	StorageDir      string `json:"storage_dir"`
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

	CurrentConfig = *cfg
	CurrentPath = path

	return cfg, nil
}
