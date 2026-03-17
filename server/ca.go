package server

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
)

const (
	caCertFile     = "ca-cert.pem"
	caKeyFile      = "ca-key.pem"
	serverCertFile = "server-cert.pem"
	serverKeyFile  = "server-key.pem"
)

func caDir() string {
	return filepath.Join(config.CurrentConfig.Keystore.StorageDir, "ca")
}

// EnsureCA checks if a CA cert exists on disk. If not, generates a new
// ECDSA P-256 CA, saves both cert and key to disk (0600), and sends the
// CA cert to CertKit via /update-ca-info.
func EnsureCA() error {
	dir := caDir()
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err != nil {
			return fmt.Errorf("CA cert exists but CA key missing at %s", keyPath)
		}
		log.Println("CA certificate already present")
		return nil
	}

	log.Println("No CA certificate found, generating...")

	certPEM, keyPEM, err := keystoreCrypto.GenerateCA()
	if err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create CA directory: %w", err)
	}
	if err := os.WriteFile(certPath, []byte(certPEM), 0o600); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	log.Printf("CA certificate and key saved to %s", dir)

	if err := api.UpdateCAInfo(certPEM); err != nil {
		log.Printf("Warning: failed to send CA cert to CertKit: %v", err)
	} else {
		log.Println("CA certificate sent to CertKit")
	}

	return nil
}
