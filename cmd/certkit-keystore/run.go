package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
)

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "config.json", "path to config file")
	fs.Parse(args)

	v := Version()
	log.Printf("certkit-keystore %s (commit: %s, built: %s)", v.Version, v.Commit, v.Date)

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("CertKit Base URL: %s", cfg.CertkitBaseUrl)
	if cfg.Keystore != nil {
		log.Printf("Keystore Base URL: %s", cfg.Keystore.BaseUrl)
	}

	if !cfg.Keystore.Initialized {
		log.Println("Keystore not yet initialized, registering with CertKit...")
		if err := doRegister(cfg); err != nil {
			log.Fatalf("Registration failed: %v", err)
		}
		log.Println("Registration complete")
	}

	// Initial poll
	log.Println("Starting polling loop...")
	if resp, err := api.PollForConfiguration(v); err != nil {
		log.Printf("Initial poll failed: %v", err)
	} else {
		log.Printf("", resp)
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if resp, err := api.PollForConfiguration(v); err != nil {
			log.Printf("Poll failed: %#v", err)
		} else {
			log.Printf("", resp)
		}
	}
}

func doRegister(cfg *config.Config) error {
	v := Version()
	resp, err := api.RegisterKeystore(v)
	if err != nil {
		return fmt.Errorf("register keystore: %w", err)
	}

	log.Printf("Registered with CertKit, keystore ID confirmed: %s", resp.KeystoreId)

	cfg.Keystore.Initialized = true
	config.CurrentConfig = *cfg

	return config.SaveConfig(cfg, config.CurrentPath)
}
