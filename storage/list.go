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
	// CollectionId is the collection directory the certificate is in, or ""
	// for a certificate stored before v2 that hasn't been moved yet.
	CollectionId string
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

// ListStoredCerts lists the certificates in the storage directory: those in
// collection directories, then any stored before v2.
func ListStoredCerts() ([]StoredCert, error) {
	entries, err := os.ReadDir(config.CurrentConfig.Keystore.StorageDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var certs []StoredCert
	if collections, err := os.ReadDir(collectionsDir()); err == nil {
		for _, collection := range collections {
			if !collection.IsDir() {
				continue
			}
			certDirs, err := os.ReadDir(filepath.Join(collectionsDir(), collection.Name()))
			if err != nil {
				continue
			}
			for _, certDir := range certDirs {
				if certDir.IsDir() {
					certs = append(certs, readStoredCert(collection.Name(), certDir.Name(), certRootDir(collection.Name(), certDir.Name())))
				}
			}
		}
	}

	for _, entry := range entries {
		if entry.IsDir() && isLegacyCertDirName(entry.Name()) {
			certs = append(certs, readStoredCert("", entry.Name(), legacyCertRootDir(entry.Name())))
		}
	}
	return certs, nil
}

func readStoredCert(collectionId string, customCertId string, root string) StoredCert {
	sc := StoredCert{CollectionId: collectionId, CustomCertId: customCertId}

	if subdirs, err := os.ReadDir(root); err == nil {
		for _, sub := range subdirs {
			if sub.IsDir() && sub.Name() != "csr" {
				sc.Versions++
			}
		}
	}

	if hasPendingCSRIn(root) {
		sc.CSRPEM, _ = os.ReadFile(filepath.Join(csrDir(root), "csr.pem"))
	}

	data, err := os.ReadFile(metadataPath(root))
	if err != nil {
		return sc
	}
	var meta CertMetadata
	if err := json.Unmarshal(data, &meta); err != nil || meta.LatestCert == nil {
		return sc
	}
	sc.Latest = meta.LatestCert

	dir := issuedCertDir(root, meta.LatestCert.SHA1)
	sc.CertPEM, _ = os.ReadFile(filepath.Join(dir, "cert.pem"))
	if key, err := os.ReadFile(filepath.Join(dir, "key.pem")); err == nil {
		sc.KeyStored = true
		_, sc.KeyEncrypted = keystoreCrypto.EncryptedKeyID(key)
	}
	return sc
}
