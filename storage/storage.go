package storage

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
)

type CertMetadata struct {
	LatestCert *api.IssuedCert `json:"latestCert"`
}

// --- path helpers ---

func certRootDir(customCertId string) string {
	return filepath.Join(config.CurrentConfig.Keystore.StorageDir, customCertId)
}

func issuedCertDir(customCertId string, sha1 string) string {
	return filepath.Join(certRootDir(customCertId), strings.ToLower(sha1))
}

func csrDir(customCertId string) string {
	return filepath.Join(certRootDir(customCertId), "csr")
}

func metadataPath(customCertId string) string {
	return filepath.Join(certRootDir(customCertId), "metadata.json")
}

// --- file helpers ---

func ensureDir(dir string) error {
	return os.MkdirAll(dir, 0o755)
}

func writeFileIfMissing(path string, content []byte) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return false, fmt.Errorf("could not write %s: %w", path, err)
	}
	return true, nil
}

// --- public API ---

// EnsureCertOnDisk checks if cert.pem, chain.pem, and key.pem exist for the
// given certificate. If any are missing, it writes them. Returns true if any
// files were written.
func EnsureCertOnDisk(customCertId string, cert *api.IssuedCert) (bool, error) {
	dir := issuedCertDir(customCertId, cert.SHA1)

	if err := ensureDir(dir); err != nil {
		return false, fmt.Errorf("could not create directory: %w", err)
	}

	files := map[string]string{
		"cert.pem":  cert.PEM,
		"chain.pem": cert.Chain,
	}
	if cert.Key != "" {
		files["key.pem"] = cert.Key
	}

	wrote := false
	for name, content := range files {
		w, err := writeFileIfMissing(filepath.Join(dir, name), []byte(content))
		if err != nil {
			return false, err
		}
		if w {
			wrote = true
		}
	}

	return wrote, nil
}

// IsKeyOnDisk checks if key.pem exists in the cert's SHA1 directory.
// Returns (true, nil) if found, (false, error) if not.
func IsKeyOnDisk(customCertId string, sha1 string) (bool, error) {
	path := filepath.Join(issuedCertDir(customCertId, sha1), "key.pem")
	if _, err := os.Stat(path); err != nil {
		return false, fmt.Errorf("key not found at %s", path)
	}
	return true, nil
}

// EnsureMetadata writes or updates metadata.json if the latest cert SHA1
// doesn't match what's on disk.
func EnsureMetadata(customCertId string, cert *api.IssuedCert) (bool, error) {
	path := metadataPath(customCertId)

	if data, err := os.ReadFile(path); err == nil {
		var existing CertMetadata
		if err := json.Unmarshal(data, &existing); err == nil {
			if existing.LatestCert != nil && existing.LatestCert.SHA1 == cert.SHA1 {
				return false, nil
			}
		}
	}

	if err := ensureDir(certRootDir(customCertId)); err != nil {
		return false, fmt.Errorf("create directory: %w", err)
	}

	data, err := json.MarshalIndent(CertMetadata{LatestCert: cert}, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal metadata: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return false, fmt.Errorf("write metadata: %w", err)
	}

	return true, nil
}

// HasPendingCSR returns true if there is a csr/key.pem on disk for this cert.
func HasPendingCSR(customCertId string) bool {
	_, err := os.Stat(filepath.Join(csrDir(customCertId), "key.pem"))
	return err == nil
}

// MatchAndAdoptCSRKey checks if the issued cert's public key matches the
// pending CSR private key. If so, it copies the CSR key into the cert
// directory as key.pem, and removes the csr/ directory.
func MatchAndAdoptCSRKey(customCertId string, cert *api.IssuedCert) (bool, error) {
	cDir := csrDir(customCertId)
	keyPEMBytes, err := os.ReadFile(filepath.Join(cDir, "key.pem"))
	if err != nil {
		return false, fmt.Errorf("read csr key: %w", err)
	}

	privKey, err := parsePrivateKey(keyPEMBytes)
	if err != nil {
		return false, fmt.Errorf("parse csr private key: %w", err)
	}

	certPubKey, err := parseCertPublicKey([]byte(cert.PEM))
	if err != nil {
		return false, fmt.Errorf("parse cert public key: %w", err)
	}

	if !publicKeysEqual(privKey, certPubKey) {
		return false, nil
	}

	// Keys match — copy key.pem and csr.pem into the cert directory
	iDir := issuedCertDir(customCertId, cert.SHA1)
	if err := ensureDir(iDir); err != nil {
		return false, fmt.Errorf("create cert directory: %w", err)
	}

	if err := os.WriteFile(filepath.Join(iDir, "key.pem"), keyPEMBytes, 0o600); err != nil {
		return false, fmt.Errorf("write key.pem: %w", err)
	}

	if csrPEMBytes, err := os.ReadFile(filepath.Join(cDir, "csr.pem")); err == nil {
		if err := os.WriteFile(filepath.Join(iDir, "csr.pem"), csrPEMBytes, 0o600); err != nil {
			return false, fmt.Errorf("write csr.pem: %w", err)
		}
	}

	if err := os.RemoveAll(cDir); err != nil {
		return false, fmt.Errorf("remove csr directory: %w", err)
	}

	return true, nil
}

// SaveCSR writes csr.pem and key.pem to {storageDir}/{customCertId}/csr/.
func SaveCSR(customCertId string, csrPEM string, keyPEM string) error {
	dir := csrDir(customCertId)

	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	if err := os.WriteFile(filepath.Join(dir, "csr.pem"), []byte(csrPEM), 0o600); err != nil {
		return fmt.Errorf("write csr.pem: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte(keyPEM), 0o600); err != nil {
		return fmt.Errorf("write key.pem: %w", err)
	}

	return nil
}

// --- crypto helpers ---

func parsePrivateKey(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func parseCertPublicKey(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert.PublicKey, nil
}

func publicKeysEqual(privKey any, pubKey any) bool {
	switch priv := privKey.(type) {
	case *ecdsa.PrivateKey:
		pub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return priv.PublicKey.Equal(pub)
	case *rsa.PrivateKey:
		pub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return priv.PublicKey.Equal(pub)
	default:
		return false
	}
}
