package storage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
)

// Private CA keys the keystore holds for CertKit are stored under
// <storageDir>/private-cas/<caId>/: key.pem, plus cert.pem once the CA's
// certificate is known and csr.pem for a key created with a CSR.
const privateCAsDirName = "private-cas"

func privateCAsDir() string {
	return filepath.Join(config.CurrentConfig.Keystore.StorageDir, privateCAsDirName)
}

func privateCADir(caId string) (string, error) {
	if !IsSafeId(caId) {
		return "", fmt.Errorf("invalid CA ID %q", caId)
	}
	return filepath.Join(privateCAsDir(), caId), nil
}

// ReadPrivateCAKey returns the plaintext key of a private CA. The error wraps
// os.ErrNotExist when the keystore doesn't hold one.
func ReadPrivateCAKey(caId string) ([]byte, error) {
	dir, err := privateCADir(caId)
	if err != nil {
		return nil, err
	}
	return ReadPrivateKey(filepath.Join(dir, "key.pem"))
}

// SavePrivateCAKey encrypts and stores a private CA's new key. It never
// replaces one: a CA key is lost for good once overwritten.
func SavePrivateCAKey(caId string, keyPEM []byte) error {
	dir, err := privateCADir(caId)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "key.pem")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("CA %s already has a key", caId)
	}
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	return WritePrivateKey(path, keyPEM)
}

// SavePrivateCACertificate stores a private CA's certificate next to its key.
func SavePrivateCACertificate(caId string, certPEM string) error {
	return savePrivateCAFile(caId, "cert.pem", []byte(certPEM))
}

// SavePrivateCACSR stores the CSR created for a private CA's key.
func SavePrivateCACSR(caId string, csrPEM string) error {
	return savePrivateCAFile(caId, "csr.pem", []byte(csrPEM))
}

func savePrivateCAFile(caId string, name string, data []byte) error {
	dir, err := privateCADir(caId)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return nil
	}
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	return writeFileAtomic(path, data)
}

// StoredCA describes one private CA directory, for the status page. The key
// is checked for presence and encryption but never decrypted.
type StoredCA struct {
	Id           string
	CertPEM      []byte
	CSRPEM       []byte
	KeyStored    bool
	KeyEncrypted bool
}

// ListPrivateCAs lists the private CAs whose keys are in the storage directory.
func ListPrivateCAs() ([]StoredCA, error) {
	entries, err := os.ReadDir(privateCAsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var cas []StoredCA
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(privateCAsDir(), entry.Name())
		ca := StoredCA{Id: entry.Name()}
		ca.CertPEM, _ = os.ReadFile(filepath.Join(dir, "cert.pem"))
		ca.CSRPEM, _ = os.ReadFile(filepath.Join(dir, "csr.pem"))
		if key, err := os.ReadFile(filepath.Join(dir, "key.pem")); err == nil {
			ca.KeyStored = true
			_, ca.KeyEncrypted = keystoreCrypto.EncryptedKeyID(key)
		}
		cas = append(cas, ca)
	}
	return cas, nil
}
