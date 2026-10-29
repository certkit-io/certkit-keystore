package storage

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
)

// CertInfo identifies the latest issued cert. The PEMs live in the cert's
// SHA1 directory; nothing secret is stored here. The JSON names match
// api.IssuedCert, so metadata written by older versions still parses.
type CertInfo struct {
	Id           int       `json:"id"`
	SHA1         string    `json:"sha1"`
	SHA256       string    `json:"sha256"`
	SerialNumber string    `json:"serialNumber"`
	IssueDate    time.Time `json:"issueDate"`
}

type CertMetadata struct {
	LatestCert *CertInfo `json:"latestCert"`
}

func marshalMetadata(meta CertMetadata) ([]byte, error) {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	return data, nil
}

// --- path helpers ---

// Certificates are stored per collection, under
// <storageDir>/collections/<collectionId>/<customCertId>. Keystores before
// v2 served a single collection and stored them directly under the storage
// directory; AdoptLegacyCert moves those into place.
const (
	caDirName          = "ca"
	collectionsDirName = "collections"
)

func collectionsDir() string {
	return filepath.Join(config.CurrentConfig.Keystore.StorageDir, collectionsDirName)
}

func certRootDir(collectionId string, customCertId string) string {
	return filepath.Join(collectionsDir(), collectionId, customCertId)
}

func legacyCertRootDir(customCertId string) string {
	return filepath.Join(config.CurrentConfig.Keystore.StorageDir, customCertId)
}

// isLegacyCertDirName reports whether a directory directly under the storage
// directory holds a certificate stored before v2.
func isLegacyCertDirName(name string) bool {
	return name != caDirName && name != collectionsDirName && name != privateCAsDirName
}

func issuedCertDir(certRoot string, sha1 string) string {
	return filepath.Join(certRoot, strings.ToLower(sha1))
}

func csrDir(certRoot string) string {
	return filepath.Join(certRoot, "csr")
}

func metadataPath(certRoot string) string {
	return filepath.Join(certRoot, "metadata.json")
}

// IsSafeId reports whether id, a collection or certificate ID from CertKit,
// can be used as a directory name: letters, digits, '-' and '_' only.
func IsSafeId(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
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

// writeKeyIfMissing encrypts and writes key.pem if it doesn't exist yet.
func writeKeyIfMissing(path string, keyPEM []byte) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	}
	if err := WritePrivateKey(path, keyPEM); err != nil {
		return false, fmt.Errorf("could not write %s: %w", path, err)
	}
	return true, nil
}

// --- public API ---

// EnsureCertOnDisk checks if cert.pem, chain.pem, and key.pem exist for the
// given certificate. If any are missing, it writes them. Returns true if any
// files were written.
func EnsureCertOnDisk(collectionId string, customCertId string, cert *api.IssuedCert) (bool, error) {
	dir := issuedCertDir(certRootDir(collectionId, customCertId), cert.SHA1)

	if err := ensureDir(dir); err != nil {
		return false, fmt.Errorf("could not create directory: %w", err)
	}

	files := map[string]string{
		"cert.pem":  cert.PEM,
		"chain.pem": cert.Chain,
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

	if cert.Key != "" {
		w, err := writeKeyIfMissing(filepath.Join(dir, "key.pem"), []byte(cert.Key))
		if err != nil {
			return false, err
		}
		if w {
			wrote = true
		}
	}

	return wrote, nil
}

// IsKeyOnDisk checks that key.pem exists in the cert's SHA1 directory and can
// be decrypted. Returns (true, nil) if so, (false, error) if not.
func IsKeyOnDisk(collectionId string, customCertId string, sha1 string) (bool, error) {
	path := filepath.Join(issuedCertDir(certRootDir(collectionId, customCertId), sha1), "key.pem")
	if _, err := os.Stat(path); err != nil {
		return false, fmt.Errorf("key not found at %s", path)
	}
	if err := CheckPrivateKey(path); err != nil {
		return false, fmt.Errorf("key at %s could not be read: %w", path, err)
	}
	return true, nil
}

// EnsureMetadata writes or updates metadata.json if it doesn't already
// describe the latest cert in the current (slim) format.
func EnsureMetadata(collectionId string, customCertId string, cert *api.IssuedCert) (bool, error) {
	root := certRootDir(collectionId, customCertId)
	path := metadataPath(root)

	data, err := marshalMetadata(CertMetadata{LatestCert: &CertInfo{
		Id:           cert.Id,
		SHA1:         cert.SHA1,
		SHA256:       cert.SHA256,
		SerialNumber: cert.SerialNumber,
		IssueDate:    cert.IssueDate,
	}})
	if err != nil {
		return false, err
	}

	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return false, nil
	}

	if err := ensureDir(root); err != nil {
		return false, fmt.Errorf("create directory: %w", err)
	}

	if err := writeFileAtomic(path, data); err != nil {
		return false, fmt.Errorf("write metadata: %w", err)
	}

	return true, nil
}

// HasPendingCSR returns true if there is a csr/key.pem on disk for this cert.
func HasPendingCSR(collectionId string, customCertId string) bool {
	return hasPendingCSRIn(certRootDir(collectionId, customCertId))
}

func hasPendingCSRIn(certRoot string) bool {
	_, err := os.Stat(filepath.Join(csrDir(certRoot), "key.pem"))
	return err == nil
}

// MatchAndAdoptCSRKey checks if the issued cert's public key matches the
// pending CSR private key. If so, it copies the CSR key into the cert
// directory as key.pem, and removes the csr/ directory.
func MatchAndAdoptCSRKey(collectionId string, customCertId string, cert *api.IssuedCert) (bool, error) {
	root := certRootDir(collectionId, customCertId)
	cDir := csrDir(root)
	keyPEMBytes, err := ReadPrivateKey(filepath.Join(cDir, "key.pem"))
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
	iDir := issuedCertDir(root, cert.SHA1)
	if err := ensureDir(iDir); err != nil {
		return false, fmt.Errorf("create cert directory: %w", err)
	}

	if err := WritePrivateKey(filepath.Join(iDir, "key.pem"), keyPEMBytes); err != nil {
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

// SaveCSR writes csr.pem and key.pem to the certificate's csr/ directory.
func SaveCSR(collectionId string, customCertId string, csrPEM string, keyPEM string) error {
	dir := csrDir(certRootDir(collectionId, customCertId))

	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	if err := os.WriteFile(filepath.Join(dir, "csr.pem"), []byte(csrPEM), 0o600); err != nil {
		return fmt.Errorf("write csr.pem: %w", err)
	}

	if err := WritePrivateKey(filepath.Join(dir, "key.pem"), []byte(keyPEM)); err != nil {
		return fmt.Errorf("write key.pem: %w", err)
	}

	return nil
}

// ReadLatestCert reads the latest issued certificate files from disk for the
// given certificate. Returns the PEM contents and SHA1 thumbprint.
func ReadLatestCert(collectionId string, customCertId string) (*CertFiles, error) {
	if !IsSafeId(collectionId) || !IsSafeId(customCertId) {
		return nil, fmt.Errorf("invalid certificate %q in collection %q", customCertId, collectionId)
	}

	root := certRootDir(collectionId, customCertId)
	if _, err := os.Stat(root); os.IsNotExist(err) {
		// Stored before v2 and not moved into its collection yet; the next
		// poll does that.
		root = legacyCertRootDir(customCertId)
	}

	data, err := os.ReadFile(metadataPath(root))
	if err != nil {
		return nil, fmt.Errorf("read metadata: %w", err)
	}

	var meta CertMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}
	if meta.LatestCert == nil {
		return nil, fmt.Errorf("no latest certificate in metadata")
	}

	sha1 := meta.LatestCert.SHA1
	dir := issuedCertDir(root, sha1)

	certPEM, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return nil, fmt.Errorf("read cert.pem: %w", err)
	}

	keyPEM, err := ReadPrivateKey(filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, fmt.Errorf("read key.pem: %w", err)
	}

	chainPEM, _ := os.ReadFile(filepath.Join(dir, "chain.pem")) // chain may not exist

	return &CertFiles{
		CertPEM:  string(certPEM),
		KeyPEM:   string(keyPEM),
		ChainPEM: string(chainPEM),
		SHA1:     sha1,
	}, nil
}

type CertFiles struct {
	CertPEM  string
	KeyPEM   string
	ChainPEM string
	SHA1     string
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
