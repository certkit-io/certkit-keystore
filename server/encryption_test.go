package server

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
	"github.com/certkit-io/certkit-keystore/storage"
)

func setEncryptionKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, keystoreCrypto.EncryptionKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetEncryptionKey(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// setupServer points the server package at a temp storage directory and
// records CA certs sent to CertKit instead of sending them.
func setupServer(t *testing.T) (sentCAs *[]string) {
	t.Helper()
	prevConfig, prevUpdate := config.CurrentConfig, updateCAInfo
	t.Cleanup(func() {
		config.CurrentConfig = prevConfig
		updateCAInfo = prevUpdate
	})

	config.CurrentConfig = config.Config{Keystore: &config.KeystoreInfo{
		Host:       "keystore.example.com",
		Port:       "443",
		StorageDir: t.TempDir(),
	}}
	sent := []string{}
	updateCAInfo = func(certPEM string) error {
		sent = append(sent, certPEM)
		return nil
	}
	return &sent
}

func assertEncrypted(t *testing.T, path string, key []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if kid, enc := keystoreCrypto.EncryptedKeyID(data); !enc || kid != keystoreCrypto.KeyID(key) {
		t.Fatalf("%s is not encrypted with the current key", path)
	}
}

func TestCAAndServerKeysEncrypted(t *testing.T) {
	sent := setupServer(t)
	key := setEncryptionKey(t)

	if err := EnsureCA(); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if len(*sent) != 1 {
		t.Fatalf("CA sent to CertKit %d times, want 1", len(*sent))
	}
	assertEncrypted(t, filepath.Join(caDir(), caKeyFile), key)

	m, err := NewTLSManager()
	if err != nil {
		t.Fatalf("NewTLSManager: %v", err)
	}
	if m.cert == nil {
		t.Fatal("no server certificate loaded")
	}
	assertEncrypted(t, filepath.Join(caDir(), serverKeyFile), key)

	// A restart with the same key reuses everything.
	if err := EnsureCA(); err != nil {
		t.Fatalf("second EnsureCA: %v", err)
	}
	if len(*sent) != 1 {
		t.Fatal("an existing, readable CA was regenerated")
	}
	if _, err := NewTLSManager(); err != nil {
		t.Fatalf("second NewTLSManager: %v", err)
	}
}

func TestPlaintextCAFromOlderVersion(t *testing.T) {
	sent := setupServer(t)
	setEncryptionKey(t)

	certPEM, keyPEM, err := keystoreCrypto.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(caDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(caDir(), caCertFile), []byte(certPEM), 0o600)
	os.WriteFile(filepath.Join(caDir(), caKeyFile), []byte(keyPEM), 0o600)

	if err := EnsureCA(); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if len(*sent) != 0 {
		t.Fatal("a readable plaintext CA was regenerated")
	}
	if _, err := NewTLSManager(); err != nil {
		t.Fatalf("NewTLSManager with a plaintext CA key: %v", err)
	}
}
