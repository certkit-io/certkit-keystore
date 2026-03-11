package main

import (
	"log"
	"os"
	"time"

	"github.com/certkit-io/certkit-keystore/config"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	log.Printf("certkit-keystore %s (commit: %s, built: %s)", version, commit, buildDate)

	configPath := "config.json"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("CertKit Base URL: %s", cfg.CertkitBaseUrl)
	log.Printf("Keystore Base URL: %s", cfg.KeystoreBaseUrl)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("hi from certkit-keystore")
	}
}
