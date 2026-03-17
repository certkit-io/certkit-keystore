package main

import (
	"flag"
	"log"

	"github.com/certkit-io/certkit-keystore/config"
)

func installCmd(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	key := fs.String("key", "", "registration key in format {app_id}.{keystore_id} (or set CERTKIT_REGISTRATION_KEY)")
	configPath := fs.String("config", "config.json", "path to config file")
	host := fs.String("host", "", "keystore hostname or IP (e.g. keystore.example.com or 192.168.1.50)")
	port := fs.String("port", config.DefaultKeystorePort, "keystore listen port")
	storageDir := fs.String("storage-dir", config.DefaultStorageDir, "directory for key storage")
	fs.Parse(args)

	v := Version()
	log.Printf("certkit-keystore %s (commit: %s, built: %s)", v.Version, v.Commit, v.Date)

	// If a config already exists and has been initialized, skip creation
	existing, err := config.ReadConfig(*configPath)
	if err == nil && existing.Keystore != nil && existing.Keystore.Initialized {
		log.Printf("Config at %s is already initialized, skipping configuration", *configPath)
	} else {
		if err := config.CreateInitialConfig(*configPath, *key, *host, *port, *storageDir); err != nil {
			log.Fatalf("Install failed: %v", err)
		}
		log.Printf("Config written to %s", *configPath)
	}

	// TODO: install as Windows service
	// TODO: install as systemd service (Linux)
	log.Println("Service installation not yet implemented")
}
