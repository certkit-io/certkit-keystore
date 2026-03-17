package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
)

const rotationWindow = 30 * 24 * time.Hour

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

// serverCertSANMismatch returns true if the server cert's SANs don't match
// the host derived from config.Keystore.BaseUrl().
func serverCertSANMismatch(certPath string) bool {
	hosts, err := hostsFromBaseURL(config.CurrentConfig.Keystore.BaseUrl())
	if err != nil {
		return true
	}

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

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			if !containsIP(cert.IPAddresses, ip) {
				log.Printf("Server cert missing IP SAN %s, will re-issue", h)
				return true
			}
		} else {
			if !containsString(cert.DNSNames, h) {
				log.Printf("Server cert missing DNS SAN %s, will re-issue", h)
				return true
			}
		}
	}
	return false
}

func containsIP(ips []net.IP, target net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(target) {
			return true
		}
	}
	return false
}

func containsString(strs []string, target string) bool {
	for _, s := range strs {
		if s == target {
			return true
		}
	}
	return false
}

// TLSManager holds the current server certificate and supports hot-swap
// rotation via GetCertificate.
type TLSManager struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

func NewTLSManager() (*TLSManager, error) {
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

	if serverCertNeedsRotation(certPath) || serverCertSANMismatch(certPath) {
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

	hosts, err := hostsFromBaseURL(cfg.Keystore.BaseUrl())
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

// CheckRotation re-issues the server leaf cert if it is within 30 days of expiry.
func (m *TLSManager) CheckRotation() {
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

// StartServer starts the HTTPS server with TLS 1.3 and registers all routes.
func (m *TLSManager) StartServer() error {
	cfg := &config.CurrentConfig

	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: m.GetCertificate,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handleRoot)
	mux.HandleFunc("POST /api/agent/v1/{agentSqid}/fetch-certificate", handleFetchCertificate)
	mux.HandleFunc("POST /api/agent/v1/{agentSqid}/fetch-pfx", handleFetchPfx)

	srv := &http.Server{
		Addr:      ":" + cfg.Keystore.Port,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting HTTPS server on :%s", cfg.Keystore.Port)
	return srv.ListenAndServeTLS("", "")
}
