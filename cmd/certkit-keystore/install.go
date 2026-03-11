package main

import (
	"flag"
	"log"

	"github.com/certkit-io/certkit-keystore/config"
)

func installCmd(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	id := fs.String("id", "", "keystore ID (or set CERTKIT_KEYSTORE_ID)")
	configPath := fs.String("config", "config.json", "path to config file")
	port := fs.String("port", config.DefaultKeystorePort, "keystore listen port")
	storageDir := fs.String("storage-dir", config.DefaultStorageDir, "directory for key storage")
	fs.Parse(args)

	log.Printf("certkit-keystore %s (commit: %s, built: %s)", version, commit, buildDate)

	if err := config.CreateInitialConfig(*configPath, *id, *port, *storageDir); err != nil {
		log.Fatalf("Install failed: %v", err)
	}

	log.Printf("Config written to %s", *configPath)

	// TODO: install as system service (systemd / Windows service)
	log.Println("Service installation not yet implemented")
}
