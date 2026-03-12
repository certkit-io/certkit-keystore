package main

import (
	"flag"
	"fmt"
	"log"
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
		processPollResponse(v, resp)
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if resp, err := api.PollForConfiguration(v); err != nil {
			log.Printf("Poll failed: %v", err)
		} else {
			processPollResponse(v, resp)
		}
	}
}

func processPollResponse(v config.VersionInfo, resp *api.PollResponse) {
	for _, cert := range resp.Certificates {
		// If there's an issued cert, ensure files and metadata are on disk
		if cert.LatestIssuedCert != nil {
			// If the cert has no key but we have a pending CSR, check if it matches
			if cert.LatestIssuedCert.Key == "" && !storage.IsKeyOnDisk(cert.CustomCertId, cert.LatestIssuedCert.SHA1) && storage.HasPendingCSR(cert.CustomCertId) {
				matched, err := storage.MatchAndAdoptCSRKey(cert.CustomCertId, cert.LatestIssuedCert)
				if err != nil {
					log.Printf("Failed to match CSR key for %s: %v", cert.CustomCertId, err)
				} else if matched {
					log.Printf("Matched CSR key to issued cert %s, adopted key", cert.CustomCertId)
				}
			}

			wrote, err := storage.EnsureCertOnDisk(cert.CustomCertId, cert.LatestIssuedCert)
			if err != nil {
				log.Printf("Failed to write cert %s to disk: %v", cert.CustomCertId, err)
			} else if wrote {
				log.Printf("Wrote cert %s (sha1: %s) to disk", cert.CustomCertId, cert.LatestIssuedCert.SHA1)
			}

			updated, err := storage.EnsureMetadata(cert.CustomCertId, cert.LatestIssuedCert)
			if err != nil {
				log.Printf("Failed to write metadata for %s: %v", cert.CustomCertId, err)
			} else if updated {
				log.Printf("Updated metadata for cert %s", cert.CustomCertId)
			}
		}

		// If there's a CSR request, generate, save, and submit it
		if cert.CSR != nil {
			log.Printf("CSR requested for cert %s (algorithm: %s, SANs: %v)",
				cert.CustomCertId, cert.CSR.KeyAlgorithm, cert.CSR.SANs)

			csrPEM, keyPEM, err := keystoreCrypto.GenerateCSR(cert.CSR.SANs, string(cert.CSR.KeyAlgorithm))
			if err != nil {
				log.Printf("Failed to generate CSR for %s: %v", cert.CustomCertId, err)
				continue
			}

			if err := storage.SaveCSR(cert.CustomCertId, csrPEM, keyPEM); err != nil {
				log.Printf("Failed to save CSR for %s to disk: %v", cert.CustomCertId, err)
				continue
			}

			if err := api.SetCSR(v, cert.CustomCertId, csrPEM); err != nil {
				log.Printf("Failed to submit CSR for %s: %v", cert.CustomCertId, err)
				continue
			}

			log.Printf("CSR submitted for cert %s", cert.CustomCertId)
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
