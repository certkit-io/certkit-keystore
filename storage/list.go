package storage

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
)

// StoredCert describes one certificate directory in the storage directory,
// for the status page. Private keys are checked for presence and encryption
// but never decrypted.
type StoredCert struct {
	CustomCertId string
	// Latest is the latest issued cert from metadata.json; nil if there is none.
	Latest *CertInfo
	// CertPEM is the latest cert's cert.pem; nil if it is missing.
	CertPEM []byte
	// KeyStored reports whether the latest cert's key.pem exists, and
	// KeyEncrypted whether it is encrypted at rest.
	KeyStored    bool
	KeyEncrypted bool
	// CSRPEM is the pending CSR, if there is one.
	CSRPEM []byte
	// Versions is the number of issued certificate directories on disk.
	Versions int
}

// ListStoredCerts lists the certificates in the storage directory.
func ListStoredCerts() ([]StoredCert, error) {
	entries, err := os.ReadDir(config.CurrentConfig.Keystore.StorageDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var certs []StoredCert
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "ca" {
			continue
		}
		certs = append(certs, readStoredCert(entry.Name()))
	}
	return certs, nil
}

func readStoredCert(customCertId string) StoredCert {
	sc := StoredCert{CustomCertId: customCertId}

	if subdirs, err := os.ReadDir(certRootDir(customCertId)); err == nil {
		for _, sub := range subdirs {
			if sub.IsDir() && sub.Name() != "csr" {
				sc.Versions++
			}
		}
	}

	if HasPendingCSR(customCertId) {
		sc.CSRPEM, _ = os.ReadFile(filepath.Join(csrDir(customCertId), "csr.pem"))
	}

	data, err := os.ReadFile(metadataPath(customCertId))
	if err != nil {
		return sc
	}
	var meta CertMetadata
	if err := json.Unmarshal(data, &meta); err != nil || meta.LatestCert == nil {
		return sc
	}
	sc.Latest = meta.LatestCert

	dir := issuedCertDir(customCertId, meta.LatestCert.SHA1)
	sc.CertPEM, _ = os.ReadFile(filepath.Join(dir, "cert.pem"))
	if key, err := os.ReadFile(filepath.Join(dir, "key.pem")); err == nil {
		sc.KeyStored = true
		_, sc.KeyEncrypted = keystoreCrypto.EncryptedKeyID(key)
	}
	return sc
}
