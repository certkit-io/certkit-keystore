package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
	"github.com/certkit-io/certkit-keystore/storage"
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
		log.Printf("Keystore Base URL: %s", cfg.Keystore.BaseUrl())
	}

	if !cfg.Keystore.Initialized {
		log.Println("Keystore not yet initialized, registering with CertKit...")
		if err := doRegister(cfg); err != nil {
			log.Fatalf("Registration failed: %v", err)
		}
		log.Println("Registration complete")
	}

	// Ensure CA certificate exists
	if err := ensureCA(v); err != nil {
		log.Fatalf("Failed to ensure CA: %v", err)
	}

	// Initialize TLS and server certificate
	tlsMgr, err := newTLSManager()
	if err != nil {
		log.Fatalf("Failed to initialize TLS: %v", err)
	}

	// Run startup checks
	runStartupChecks(v)

	// Start HTTPS server
	go func() {
		if err := tlsMgr.startServer(); err != nil {
			log.Fatalf("HTTPS server failed: %v", err)
		}
	}()

	// Initial poll
	log.Println("Starting polling loop...")
	if resp, err := api.PollForConfiguration(v); err != nil {
		log.Printf("Initial poll failed: %v", err)
	} else {
		processPollResponse(v, resp)
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		tlsMgr.checkRotation()
		if resp, err := api.PollForConfiguration(v); err != nil {
			log.Printf("Poll failed: %v", err)
		} else {
			processPollResponse(v, resp)
		}
	}
}

func processPollResponse(v config.VersionInfo, resp *api.PollResponse) {
	var statuses []api.UpdateStatusItem

	for _, cert := range resp.Certificates {
		// If there's a CSR request, generate, save, and submit it
		if cert.CSR != nil {
			log.Printf("CSR requested for cert %s (algorithm: %s, SANs: %v)",
				cert.CustomCertId, cert.CSR.KeyAlgorithm, cert.CSR.SANs)

			if storage.HasPendingCSR(cert.CustomCertId) {
				msg := fmt.Sprintf("Creating new CSR for %s even though there is an existing one present", cert.CustomCertId)
				log.Println(msg)
				if logErr := api.LogKeystoreEvent(v, msg, api.LogEvents.Info, false); logErr != nil {
					log.Printf("Failed to send log to CertKit: %v", logErr)
				}
			}

			csrPEM, keyPEM, err := keystoreCrypto.GenerateCSR(cert.CSR.SANs, string(cert.CSR.KeyAlgorithm))
			if err != nil {
				log.Printf("Failed to generate CSR for %s: %v", cert.CustomCertId, err)
				statuses = append(statuses, api.UpdateStatusItem{CustomCertId: cert.CustomCertId, Status: api.CertStatuses.GeneralError, Message: err.Error()})
				continue
			}

			if err := storage.SaveCSR(cert.CustomCertId, csrPEM, keyPEM); err != nil {
				log.Printf("Failed to save CSR for %s to disk: %v", cert.CustomCertId, err)
				statuses = append(statuses, api.UpdateStatusItem{CustomCertId: cert.CustomCertId, Status: api.CertStatuses.GeneralError, Message: err.Error()})
				continue
			}

			if err := api.SetCSR(v, cert.CustomCertId, csrPEM); err != nil {
				log.Printf("Failed to submit CSR for %s: %v", cert.CustomCertId, err)
				statuses = append(statuses, api.UpdateStatusItem{CustomCertId: cert.CustomCertId, Status: api.CertStatuses.GeneralError, Message: err.Error()})
				continue
			}

			log.Printf("CSR submitted for cert %s", cert.CustomCertId)
			statuses = append(statuses, api.UpdateStatusItem{CustomCertId: cert.CustomCertId, Status: api.CertStatuses.PendingCSR})
			continue
		}

		// If there's an issued cert, ensure files and metadata are on disk
		if cert.LatestIssuedCert != nil {
			// If the cert has no key but we have a pending CSR, check if it matches
			keyOnDisk, _ := storage.IsKeyOnDisk(cert.CustomCertId, cert.LatestIssuedCert.SHA1)
			if cert.LatestIssuedCert.Key == "" && !keyOnDisk && storage.HasPendingCSR(cert.CustomCertId) {
				matched, err := storage.MatchAndAdoptCSRKey(cert.CustomCertId, cert.LatestIssuedCert)
				if err != nil {
					log.Printf("Error while matching CSR key for %s: %v", cert.CustomCertId, err)
				} else if matched {
					log.Printf("Matched CSR key to issued cert %s, adopted key", cert.CustomCertId)
				} else {
					log.Printf("Failed to match CSR key for %s: %v", cert.CustomCertId, cert.LatestIssuedCert)
				}
			}

			wrote, err := storage.EnsureCertOnDisk(cert.CustomCertId, cert.LatestIssuedCert)
			if err != nil {
				log.Printf("Failed to write cert %s to disk: %v", cert.CustomCertId, err)
				statuses = append(statuses, api.UpdateStatusItem{CustomCertId: cert.CustomCertId, Status: api.CertStatuses.CertNotStored, Message: err.Error()})
				continue
			} else if wrote {
				log.Printf("Wrote cert %s (sha1: %s) to disk", cert.CustomCertId, cert.LatestIssuedCert.SHA1)
			}

			updated, err := storage.EnsureMetadata(cert.CustomCertId, cert.LatestIssuedCert)
			if err != nil {
				log.Printf("Failed to write metadata for %s: %v", cert.CustomCertId, err)
			} else if updated {
				log.Printf("Updated metadata for cert %s", cert.CustomCertId)
			}

			// Determine final status for this cert
			if keyFound, keyErr := storage.IsKeyOnDisk(cert.CustomCertId, cert.LatestIssuedCert.SHA1); !keyFound {
				statuses = append(statuses, api.UpdateStatusItem{CustomCertId: cert.CustomCertId, Status: api.CertStatuses.KeyNotFound, Message: keyErr.Error()})
			} else {
				statuses = append(statuses, api.UpdateStatusItem{CustomCertId: cert.CustomCertId, Status: api.CertStatuses.Synced})
			}
			continue
		}

		// No issued cert — check if there's a pending CSR on disk
		if storage.HasPendingCSR(cert.CustomCertId) {
			statuses = append(statuses, api.UpdateStatusItem{CustomCertId: cert.CustomCertId, Status: api.CertStatuses.PendingCSR})
		}
	}

	if err := api.UpdateStatus(v, statuses); err != nil {
		log.Printf("Failed to send status update to CertKit: %v", err)
	}

}

func runStartupChecks(v config.VersionInfo) {
	log.Println("Running startup checks...")

	if err := checkStorageDirWritable(); err != nil {
		msg := fmt.Sprintf("Storage directory is not writable: %v", err)
		log.Printf("Startup check FAILED: %s", msg)
		if logErr := api.LogKeystoreEvent(v, msg, api.LogEvents.Startup, true); logErr != nil {
			log.Printf("Failed to send startup error to CertKit: %v", logErr)
		}
		return
	}

	log.Println("All startup checks passed")
	if logErr := api.LogKeystoreEvent(v, "Keystore running.", api.LogEvents.Startup, false); logErr != nil {
		log.Printf("Failed to send startup log to CertKit: %v", logErr)
	}
}

func checkStorageDirWritable() error {
	dir := config.CurrentConfig.Keystore.StorageDir
	testPath := filepath.Join(dir, ".certkit-healthcheck")

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create storage directory: %w", err)
	}

	testData := []byte("certkit-keystore-healthcheck")
	if err := os.WriteFile(testPath, testData, 0o600); err != nil {
		return fmt.Errorf("write test file: %w", err)
	}

	readBack, err := os.ReadFile(testPath)
	if err != nil {
		return fmt.Errorf("read test file: %w", err)
	}

	if string(readBack) != string(testData) {
		os.Remove(testPath)
		return fmt.Errorf("read-back mismatch")
	}

	if err := os.Remove(testPath); err != nil {
		return fmt.Errorf("remove test file: %w", err)
	}

	return nil
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
