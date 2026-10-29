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
	"strings"
	"sync"
	"time"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
	"github.com/certkit-io/certkit-keystore/storage"
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

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read server cert: %w", err)
	}
	keyPEM, err := storage.ReadPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("read server key: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
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

	caKeyPEM, err := storage.ReadPrivateKey(filepath.Join(caDir(), caKeyFile))
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
	if err := storage.WritePrivateKey(filepath.Join(dir, serverKeyFile), []byte(keyPEM)); err != nil {
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

	srv := &http.Server{
		Addr:      ":" + cfg.Keystore.Port,
		Handler:   newMux(),
		TLSConfig: tlsConfig,
		ErrorLog:  log.New(serverErrorWriter{}, "", 0),
	}

	log.Printf("Starting HTTPS server on :%s", cfg.Keystore.Port)
	return srv.ListenAndServeTLS("", "")
}

// serverErrorWriter passes the HTTPS server's errors on to the keystore's log,
// except for handshakes that a client ended because it doesn't trust the
// keystore's certificate.
type serverErrorWriter struct{}

func (serverErrorWriter) Write(p []byte) (int, error) {
	if line := string(p); !untrustedCertError(line) {
		log.Print(line)
	}
	return len(p), nil
}

// untrustedCertError reports whether line is the error net/http logs when a
// browser (or curl) ends the handshake because it doesn't trust the keystore's
// certificate, which browsers do on every visit: only agents are given the
// keystore's CA. Go clients, agents among them, send "bad certificate"
// instead, and that's still logged.
func untrustedCertError(line string) bool {
	line = strings.TrimSuffix(line, "\n")
	return strings.HasPrefix(line, "http: TLS handshake error from ") &&
		(strings.HasSuffix(line, ": remote error: tls: unknown certificate") ||
			strings.HasSuffix(line, ": remote error: tls: unknown certificate authority"))
}

// newMux routes the keystore's requests. Its pages are for browsers logged in
// through CertKit; CertKit validates each agent request.
func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", requireLogin(handleRoot))
	mux.HandleFunc("GET /logs", requireLogin(handleLogs))
	mux.HandleFunc("GET /logs/download", requireLogin(handleLogsDownload))
	mux.HandleFunc("GET /auth/login", handleLogin)
	mux.HandleFunc("GET /auth/callback", handleLoginCallback)
	mux.HandleFunc("POST /auth/logout", handleLogout)
	mux.HandleFunc("POST /api/agent/v1/{agentSqid}/fetch-certificate", handleFetchCertificate)
	mux.HandleFunc("POST /api/agent/v1/{agentSqid}/fetch-pfx", handleFetchPfx)
	return mux
}
