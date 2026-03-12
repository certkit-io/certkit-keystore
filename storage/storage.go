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

// EnsureCertOnDisk checks if cert.pem, chain.pem, and key.pem exist for the
// given certificate under {storageDir}/{customCertId}/{sha1}/. If any are
// missing, it writes them. Returns true if any files were written.
func EnsureCertOnDisk(customCertId string, cert *api.IssuedCert) (bool, error) {
	dir := filepath.Join(config.CurrentConfig.Keystore.StorageDir, customCertId, strings.ToLower(cert.SHA1))

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("create directory %s: %w", dir, err)
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
		path := filepath.Join(dir, name)

		if _, err := os.Stat(path); err == nil {
			continue
		}

		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return false, fmt.Errorf("write %s: %w", path, err)
		}
		wrote = true
	}

	return wrote, nil
}

// IsKeyOnDisk returns true if key.pem exists in the cert's SHA1 directory.
func IsKeyOnDisk(customCertId string, sha1 string) bool {
	keyPath := filepath.Join(config.CurrentConfig.Keystore.StorageDir, customCertId, strings.ToLower(sha1), "key.pem")
	_, err := os.Stat(keyPath)
	return err == nil
}

// EnsureMetadata writes or updates {storageDir}/{customCertId}/metadata.json
// if the latest cert SHA1 doesn't match what's on disk.
func EnsureMetadata(customCertId string, cert *api.IssuedCert) (bool, error) {
	dir := filepath.Join(config.CurrentConfig.Keystore.StorageDir, customCertId)
	path := filepath.Join(dir, "metadata.json")

	// Check if existing metadata already matches
	if data, err := os.ReadFile(path); err == nil {
		var existing CertMetadata
		if err := json.Unmarshal(data, &existing); err == nil {
			if existing.LatestCert != nil && existing.LatestCert.SHA1 == cert.SHA1 {
				return false, nil
			}
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("create directory %s: %w", dir, err)
	}

	meta := CertMetadata{LatestCert: cert}
	data, err := json.MarshalIndent(meta, "", "  ")
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
	keyPath := filepath.Join(config.CurrentConfig.Keystore.StorageDir, customCertId, "csr", "key.pem")
	_, err := os.Stat(keyPath)
	return err == nil
}

// MatchAndAdoptCSRKey checks if the issued cert's public key matches the
// pending CSR private key. If so, it copies the CSR key into the cert
// directory as key.pem, and removes the csr/ directory.
func MatchAndAdoptCSRKey(customCertId string, cert *api.IssuedCert) (bool, error) {
	csrDir := filepath.Join(config.CurrentConfig.Keystore.StorageDir, customCertId, "csr")
	csrKeyPath := filepath.Join(csrDir, "key.pem")

	keyPEMBytes, err := os.ReadFile(csrKeyPath)
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

	// Keys match — write key.pem into the cert directory
	certDir := filepath.Join(config.CurrentConfig.Keystore.StorageDir, customCertId, strings.ToLower(cert.SHA1))
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return false, fmt.Errorf("create cert directory: %w", err)
	}

	if err := os.WriteFile(filepath.Join(certDir, "key.pem"), keyPEMBytes, 0o600); err != nil {
		return false, fmt.Errorf("write key.pem: %w", err)
	}

	// Clean up csr directory
	if err := os.RemoveAll(csrDir); err != nil {
		return false, fmt.Errorf("remove csr directory: %w", err)
	}

	return true, nil
}

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

// SaveCSR writes csr.pem and key.pem to {storageDir}/{customCertId}/csr/.
func SaveCSR(customCertId string, csrPEM string, keyPEM string) error {
	dir := filepath.Join(config.CurrentConfig.Keystore.StorageDir, customCertId, "csr")

	if err := os.MkdirAll(dir, 0o755); err != nil {
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
