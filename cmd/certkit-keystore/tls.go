package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
)

const (
	caCertFile     = "ca-cert.pem"
	caKeyFile      = "ca-key.pem"
	serverCertFile = "server-cert.pem"
	serverKeyFile  = "server-key.pem"
	rotationWindow = 30 * 24 * time.Hour
)

func caDir() string {
	return filepath.Join(config.CurrentConfig.Keystore.StorageDir, "ca")
}

// ensureCA checks if a CA cert exists on disk. If not, generates a new
// ECDSA P-256 CA, saves both cert and key to disk (0600), and sends the
// CA cert to CertKit via /update-info.
func ensureCA(v config.VersionInfo) error {
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

	if err := api.UpdateCAInfo(v, certPEM); err != nil {
		log.Printf("Warning: failed to send CA cert to CertKit: %v", err)
	} else {
		log.Println("CA certificate sent to CertKit")
	}

	return nil
}

func hostsFromBaseURL(baseURL string) ([]string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("no host in base URL: %s", baseURL)
	}
	return []string{host}, nil
}

func serverCertNeedsRotation(certPath string) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return true
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return time.Until(cert.NotAfter) < rotationWindow
}

// TLSManager holds the current server certificate and supports hot-swap
// rotation via GetCertificate.
type TLSManager struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

func newTLSManager() (*TLSManager, error) {
	m := &TLSManager{}
	if err := m.ensureServerCert(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *TLSManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert, nil
}

func (m *TLSManager) ensureServerCert() error {
	certPath := filepath.Join(caDir(), serverCertFile)

	if serverCertNeedsRotation(certPath) {
		if err := m.issueServerCert(); err != nil {
			return err
		}
	}

	return m.loadServerCert()
}

func (m *TLSManager) loadServerCert() error {
	certPath := filepath.Join(caDir(), serverCertFile)
	keyPath := filepath.Join(caDir(), serverKeyFile)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load server cert: %w", err)
	}

	m.mu.Lock()
	m.cert = &cert
	m.mu.Unlock()

	return nil
}

func (m *TLSManager) issueServerCert() error {
	cfg := &config.CurrentConfig

	caCertPEM, err := os.ReadFile(filepath.Join(caDir(), caCertFile))
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}

	caKeyPEM, err := os.ReadFile(filepath.Join(caDir(), caKeyFile))
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}

	hosts, err := hostsFromBaseURL(cfg.Keystore.BaseUrl)
	if err != nil {
		return fmt.Errorf("extract hosts: %w", err)
	}

	certPEM, keyPEM, err := keystoreCrypto.IssueServerCert(string(caCertPEM), string(caKeyPEM), hosts)
	if err != nil {
		return fmt.Errorf("issue server cert: %w", err)
	}

	dir := caDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create CA directory: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, serverCertFile), []byte(certPEM), 0o600); err != nil {
		return fmt.Errorf("write server cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, serverKeyFile), []byte(keyPEM), 0o600); err != nil {
		return fmt.Errorf("write server key: %w", err)
	}

	log.Printf("Issued new server certificate (hosts: %v)", hosts)
	return nil
}

// checkRotation re-issues the server leaf cert if it is within 30 days of expiry.
func (m *TLSManager) checkRotation() {
	certPath := filepath.Join(caDir(), serverCertFile)
	if !serverCertNeedsRotation(certPath) {
		return
	}

	log.Println("Server certificate approaching expiry, rotating...")
	if err := m.issueServerCert(); err != nil {
		log.Printf("Failed to rotate server certificate: %v", err)
		return
	}
	if err := m.loadServerCert(); err != nil {
		log.Printf("Failed to load rotated server certificate: %v", err)
		return
	}
	log.Println("Server certificate rotated successfully")
}

func (m *TLSManager) startServer() error {
	cfg := &config.CurrentConfig

	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: m.GetCertificate,
	}

	mux := http.NewServeMux()

	server := &http.Server{
		Addr:      ":" + cfg.Keystore.Port,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting HTTPS server on :%s", cfg.Keystore.Port)
	// Empty cert/key paths: Go uses GetCertificate from TLSConfig
	return server.ListenAndServeTLS("", "")
}
