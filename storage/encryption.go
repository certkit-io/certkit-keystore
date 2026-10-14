package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
)

// encryptionKey encrypts private keys at rest. It comes from CertKit at
// startup and is only ever held in memory. It is set once, before the HTTPS
// server and poll loop start, and is read-only afterwards.
var encryptionKey []byte

var errNoEncryptionKey = errors.New("encryption key not loaded")

// SetEncryptionKey sets the key used to encrypt and decrypt private keys.
func SetEncryptionKey(key []byte) error {
	if len(key) != keystoreCrypto.EncryptionKeySize {
		return fmt.Errorf("invalid encryption key length: got %d, want %d", len(key), keystoreCrypto.EncryptionKeySize)
	}
	encryptionKey = bytes.Clone(key)
	return nil
}

// WritePrivateKey encrypts a plaintext private key PEM and writes it to path.
// Plaintext is never written: without an encryption key this fails.
func WritePrivateKey(path string, plaintextPEM []byte) error {
	if encryptionKey == nil {
		return errNoEncryptionKey
	}
	encrypted, err := keystoreCrypto.EncryptPrivateKeyPEM(encryptionKey, plaintextPEM)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, encrypted)
}

// ReadPrivateKey reads a private key from path and returns its plaintext PEM.
// Keys written before encryption at rest are returned as they are.
func ReadPrivateKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if _, encrypted := keystoreCrypto.EncryptedKeyID(data); encrypted && encryptionKey == nil {
		return nil, errNoEncryptionKey
	}
	return keystoreCrypto.DecryptPrivateKeyPEM(encryptionKey, data)
}

// CheckPrivateKey returns an error if the private key at path is missing or
// can't be decrypted with the current encryption key.
func CheckPrivateKey(path string) error {
	_, err := ReadPrivateKey(path)
	return err
}

// writeFileAtomic replaces path with data (mode 0600). The data goes to a
// temp file in the same directory, which is flushed and then renamed over
// path, so readers never see a partial file and a crash leaves either the old
// or the new content.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	tmpName = ""
	return nil
}

// storageFiles lists the private key files (<customCertId>/<sha1>/key.pem,
// <customCertId>/csr/key.pem, ca/ca-key.pem, ca/server-key.pem) and the
// metadata.json files in the storage directory. Listed files may not exist.
func storageFiles(root string) (keys, metadata []string, errs []error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("read storage directory: %w", err))
		}
		return nil, nil, errs
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())

		if entry.Name() == "ca" {
			keys = append(keys, filepath.Join(dir, "ca-key.pem"), filepath.Join(dir, "server-key.pem"))
			continue
		}

		subdirs, err := os.ReadDir(dir)
		if err != nil {
			errs = append(errs, fmt.Errorf("read %s: %w", dir, err))
			continue
		}
		for _, sub := range subdirs {
			if sub.IsDir() {
				keys = append(keys, filepath.Join(dir, sub.Name(), "key.pem"))
			}
		}
		metadata = append(metadata, filepath.Join(dir, "metadata.json"))
	}

	return keys, metadata, errs
}

// StartOverIfUnreadable moves the storage directory aside, to
// <storageDir>.unreadable-<timestamp>, when any private key in it was
// encrypted with a different encryption key. That happens when the directory
// was used by an earlier registration of this keystore: its key was destroyed
// with that registration in CertKit, so nothing in the directory can be read.
// Starting over lets the keystore create a new CA, which the new registration
// needs anyway, and download again the keys CertKit holds. Returns where the
// old directory was moved, or "" if nothing was moved.
func StartOverIfUnreadable() (string, error) {
	if encryptionKey == nil {
		return "", errNoEncryptionKey
	}

	root := config.CurrentConfig.Keystore.StorageDir
	currentKid := keystoreCrypto.KeyID(encryptionKey)

	// Unreadable directories are left to MigrateToEncrypted to report.
	keys, _, _ := storageFiles(root)
	unreadable := ""
	for _, path := range keys {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if kid, encrypted := keystoreCrypto.EncryptedKeyID(data); encrypted && kid != currentKid {
			unreadable = path
			break
		}
	}
	if unreadable == "" {
		return "", nil
	}

	aside := filepath.Clean(root) + ".unreadable-" + time.Now().UTC().Format("20060102T150405Z")
	log.Printf("%s was encrypted with a different encryption key; moving %s to %s and starting over", unreadable, root, aside)
	if err := os.Rename(root, aside); err != nil {
		return "", fmt.Errorf("move %s to %s: %w", root, aside, err)
	}
	return aside, nil
}

// MigrationResult summarizes a MigrateToEncrypted run.
type MigrationResult struct {
	// Encrypted is the number of plaintext private keys encrypted this run.
	Encrypted int
	// MetadataCleaned is the number of metadata.json files slimmed down.
	MetadataCleaned int
	// Failed holds one error per file that could not be migrated.
	Failed []error
}

// MigrateToEncrypted encrypts any plaintext private keys in the storage
// directory and strips certificate and key copies from metadata.json files.
// It runs at every startup, after StartOverIfUnreadable, and is safe to
// repeat; a failure on one file never stops the rest.
func MigrateToEncrypted() MigrationResult {
	var res MigrationResult
	if encryptionKey == nil {
		res.Failed = append(res.Failed, errNoEncryptionKey)
		return res
	}

	keys, metadata, errs := storageFiles(config.CurrentConfig.Keystore.StorageDir)
	res.Failed = append(res.Failed, errs...)

	for _, path := range keys {
		migrateKeyFile(path, &res)
	}

	for _, path := range metadata {
		cleaned, err := slimMetadataFile(path)
		if err != nil {
			res.Failed = append(res.Failed, err)
		} else if cleaned {
			res.MetadataCleaned++
		}
	}

	return res
}

func migrateKeyFile(path string, res *MigrationResult) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			res.Failed = append(res.Failed, fmt.Errorf("read %s: %w", path, err))
		}
		return
	}

	if _, encrypted := keystoreCrypto.EncryptedKeyID(data); encrypted {
		return
	}

	encrypted, err := keystoreCrypto.EncryptPrivateKeyPEM(encryptionKey, data)
	if err != nil {
		res.Failed = append(res.Failed, fmt.Errorf("encrypt %s: %w", path, err))
		return
	}
	if roundTrip, err := keystoreCrypto.DecryptPrivateKeyPEM(encryptionKey, encrypted); err != nil || !bytes.Equal(roundTrip, data) {
		res.Failed = append(res.Failed, fmt.Errorf("encrypt %s: round-trip check failed", path))
		return
	}
	if err := writeFileAtomic(path, encrypted); err != nil {
		res.Failed = append(res.Failed, err)
		return
	}

	log.Printf("Encrypted private key at rest: %s", path)
	res.Encrypted++
}

// slimMetadataFile rewrites a metadata.json written by older versions (which
// held the full certificate, chain and private key) in the slim format.
func slimMetadataFile(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", path, err)
	}

	var meta CertMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return false, fmt.Errorf("parse %s: %w", path, err)
	}

	slim, err := marshalMetadata(meta)
	if err != nil {
		return false, err
	}
	if bytes.Equal(slim, data) {
		return false, nil
	}

	if err := writeFileAtomic(path, slim); err != nil {
		return false, err
	}
	return true, nil
}
