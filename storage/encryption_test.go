package storage

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, keystoreCrypto.EncryptionKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// setupStorage points the storage package at a temp directory and loads a
// fresh encryption key.
func setupStorage(t *testing.T) (dir string, key []byte) {
	t.Helper()
	dir = t.TempDir()
	prevConfig, prevKey := config.CurrentConfig, encryptionKey
	t.Cleanup(func() {
		config.CurrentConfig = prevConfig
		encryptionKey = prevKey
	})

	config.CurrentConfig = config.Config{Keystore: &config.KeystoreInfo{StorageDir: dir}}
	key = randomKey(t)
	if err := SetEncryptionKey(key); err != nil {
		t.Fatal(err)
	}
	return dir, key
}

func newKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, keyPEM, err := keystoreCrypto.GenerateCSR([]string{"example.com"}, keystoreCrypto.KeyAlgorithmEC256)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(keyPEM)
}

// selfSignedCertPEM returns a certificate for the given private key PEM.
func selfSignedCertPEM(t *testing.T, keyPEM []byte) string {
	t.Helper()
	priv, err := parsePrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	signer := priv.(crypto.Signer)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func encryptWith(t *testing.T, key, plaintextPEM []byte) []byte {
	t.Helper()
	enc, err := keystoreCrypto.EncryptPrivateKeyPEM(key, plaintextPEM)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func assertEncryptedWith(t *testing.T, path string, key, wantPlain []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if kid, enc := keystoreCrypto.EncryptedKeyID(data); !enc || kid != keystoreCrypto.KeyID(key) {
		t.Fatalf("%s is not encrypted with the current key", path)
	}
	plain, err := keystoreCrypto.DecryptPrivateKeyPEM(key, data)
	if err != nil {
		t.Fatalf("decrypt %s: %v", path, err)
	}
	if !bytes.Equal(plain, wantPlain) {
		t.Fatalf("%s does not decrypt to the original key", path)
	}
}

func TestMigrateToEncrypted(t *testing.T) {
	dir, key := setupStorage(t)

	issuedKey, csrKey, caKey, serverKey := newKeyPEM(t), newKeyPEM(t), newKeyPEM(t), newKeyPEM(t)
	certPEM := selfSignedCertPEM(t, issuedKey)

	issuedKeyPath := filepath.Join(dir, "certA", "aaaa", "key.pem")
	csrKeyPath := filepath.Join(dir, "certA", "csr", "key.pem")
	caKeyPath := filepath.Join(dir, "ca", "ca-key.pem")
	serverKeyPath := filepath.Join(dir, "ca", "server-key.pem")
	currentPath := filepath.Join(dir, "certB", "bbbb", "key.pem")
	redactedPath := filepath.Join(dir, "certD", "dddd", "key.pem")

	writeFile(t, issuedKeyPath, issuedKey)
	writeFile(t, filepath.Join(dir, "certA", "aaaa", "cert.pem"), []byte(certPEM))
	writeFile(t, csrKeyPath, csrKey)
	writeFile(t, caKeyPath, caKey)
	writeFile(t, serverKeyPath, serverKey)
	currentEnc := encryptWith(t, key, newKeyPEM(t))
	writeFile(t, currentPath, currentEnc)
	writeFile(t, redactedPath, []byte("-----BEGIN REDACTED PRIVATE KEY-----\nKEY NOT FOUND\n-----END REDACTED PRIVATE KEY-----\n"))
	writeFile(t, filepath.Join(dir, ".certkit-healthcheck"), []byte("x"))

	// metadata.json as written by older versions: the full IssuedCert.
	oldMeta, err := json.MarshalIndent(map[string]any{"latestCert": api.IssuedCert{
		Id: 7, SHA1: "AAAA", SHA256: "sha256", SerialNumber: "01",
		PEM: certPEM, Chain: "chain", Key: string(issuedKey),
	}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, metadataPath("certA"), oldMeta)

	// Older metadata and plaintext keys are readable before migration.
	files, err := ReadLatestCert("certA")
	if err != nil {
		t.Fatalf("ReadLatestCert before migration: %v", err)
	}
	if files.KeyPEM != string(issuedKey) {
		t.Fatal("ReadLatestCert before migration returned the wrong key")
	}

	res := MigrateToEncrypted()
	if res.Encrypted != 4 {
		t.Errorf("Encrypted = %d, want 4", res.Encrypted)
	}
	if len(res.Failed) != 1 || !strings.Contains(res.Failed[0].Error(), redactedPath) {
		t.Errorf("Failed = %v, want one failure for %s", res.Failed, redactedPath)
	}
	if res.MetadataCleaned != 1 {
		t.Errorf("MetadataCleaned = %d, want 1", res.MetadataCleaned)
	}

	assertEncryptedWith(t, issuedKeyPath, key, issuedKey)
	assertEncryptedWith(t, csrKeyPath, key, csrKey)
	assertEncryptedWith(t, caKeyPath, key, caKey)
	assertEncryptedWith(t, serverKeyPath, key, serverKey)
	if data, _ := os.ReadFile(currentPath); !bytes.Equal(data, currentEnc) {
		t.Error("a key already encrypted with the current key was rewritten")
	}

	meta, _ := os.ReadFile(metadataPath("certA"))
	for _, leaked := range []string{`"key"`, `"pem"`, `"chain"`, "PRIVATE KEY", "CERTIFICATE"} {
		if bytes.Contains(meta, []byte(leaked)) {
			t.Errorf("slim metadata.json still contains %s:\n%s", leaked, meta)
		}
	}

	files, err = ReadLatestCert("certA")
	if err != nil {
		t.Fatalf("ReadLatestCert after migration: %v", err)
	}
	if files.KeyPEM != string(issuedKey) || files.SHA1 != "AAAA" {
		t.Fatal("ReadLatestCert after migration returned the wrong cert")
	}

	// A second run changes nothing.
	again := MigrateToEncrypted()
	if again.Encrypted != 0 || again.MetadataCleaned != 0 || len(again.Failed) != 1 {
		t.Errorf("second run = %+v, want only the same failure", again)
	}

	// No temp files are left behind.
	filepath.WalkDir(dir, func(path string, _ os.DirEntry, _ error) error {
		if strings.Contains(filepath.Base(path), ".tmp-") {
			t.Errorf("temp file left behind: %s", path)
		}
		return nil
	})
}

func TestWritePrivateKeyRequiresKey(t *testing.T) {
	dir, _ := setupStorage(t)
	encryptionKey = nil

	path := filepath.Join(dir, "key.pem")
	if err := WritePrivateKey(path, newKeyPEM(t)); !errors.Is(err, errNoEncryptionKey) {
		t.Fatalf("err = %v, want errNoEncryptionKey", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a key file was written without an encryption key")
	}
}

func TestEnsureCertOnDiskWritesEncryptedKey(t *testing.T) {
	dir, key := setupStorage(t)
	keyPEM := newKeyPEM(t)
	cert := &api.IssuedCert{SHA1: "ABCD", PEM: selfSignedCertPEM(t, keyPEM), Chain: "chain", Key: string(keyPEM)}
	keyPath := filepath.Join(dir, "cert1", "abcd", "key.pem")

	wrote, err := EnsureCertOnDisk("cert1", cert)
	if err != nil || !wrote {
		t.Fatalf("EnsureCertOnDisk = %v, %v; want true, nil", wrote, err)
	}
	assertEncryptedWith(t, keyPath, key, keyPEM)
	if ok, err := IsKeyOnDisk("cert1", "ABCD"); !ok {
		t.Fatalf("IsKeyOnDisk: %v", err)
	}

	// An existing key is left alone.
	before, _ := os.ReadFile(keyPath)
	wrote, err = EnsureCertOnDisk("cert1", cert)
	if err != nil || wrote {
		t.Fatalf("second EnsureCertOnDisk = %v, %v; want false, nil", wrote, err)
	}
	if after, _ := os.ReadFile(keyPath); !bytes.Equal(before, after) {
		t.Fatal("an existing key was rewritten")
	}
}

func TestIsKeyOnDiskReportsUnreadableKey(t *testing.T) {
	dir, _ := setupStorage(t)
	writeFile(t, filepath.Join(dir, "cert1", "abcd", "key.pem"), encryptWith(t, randomKey(t), newKeyPEM(t)))

	if ok, err := IsKeyOnDisk("cert1", "ABCD"); ok || !errors.Is(err, keystoreCrypto.ErrKeyMismatch) {
		t.Fatalf("IsKeyOnDisk = %v, %v; want false with ErrKeyMismatch", ok, err)
	}
}

func TestStartOverIfUnreadable(t *testing.T) {
	t.Run("different key moves the directory aside", func(t *testing.T) {
		dir, key := setupStorage(t)
		writeFile(t, filepath.Join(dir, "ca", "ca-key.pem"), encryptWith(t, key, newKeyPEM(t)))
		writeFile(t, filepath.Join(dir, "certA", "aaaa", "key.pem"), newKeyPEM(t))
		writeFile(t, filepath.Join(dir, "certB", "csr", "key.pem"), encryptWith(t, randomKey(t), newKeyPEM(t)))

		aside, err := StartOverIfUnreadable()
		if err != nil {
			t.Fatalf("StartOverIfUnreadable: %v", err)
		}
		if !strings.HasPrefix(aside, filepath.Clean(dir)+".unreadable-") {
			t.Fatalf("moved to %q, want a sibling of %s", aside, dir)
		}
		t.Cleanup(func() { os.RemoveAll(aside) })

		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("storage directory still exists after starting over")
		}
		for _, rel := range []string{"ca/ca-key.pem", "certA/aaaa/key.pem", "certB/csr/key.pem"} {
			if _, err := os.Stat(filepath.Join(aside, rel)); err != nil {
				t.Errorf("%s was not moved with the directory: %v", rel, err)
			}
		}

		// The keystore carries on with an empty directory.
		if res := MigrateToEncrypted(); res.Encrypted != 0 || len(res.Failed) != 0 {
			t.Errorf("MigrateToEncrypted after starting over = %+v", res)
		}
	})

	t.Run("readable keys are left alone", func(t *testing.T) {
		dir, key := setupStorage(t)
		writeFile(t, filepath.Join(dir, "ca", "ca-key.pem"), encryptWith(t, key, newKeyPEM(t)))
		writeFile(t, filepath.Join(dir, "certA", "aaaa", "key.pem"), newKeyPEM(t))

		aside, err := StartOverIfUnreadable()
		if err != nil || aside != "" {
			t.Fatalf("StartOverIfUnreadable = %q, %v; want nothing moved", aside, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "ca", "ca-key.pem")); err != nil {
			t.Fatal("storage directory was disturbed")
		}
	})

	t.Run("missing storage directory", func(t *testing.T) {
		dir, _ := setupStorage(t)
		config.CurrentConfig.Keystore.StorageDir = filepath.Join(dir, "missing")

		if aside, err := StartOverIfUnreadable(); err != nil || aside != "" {
			t.Fatalf("StartOverIfUnreadable = %q, %v; want nothing moved", aside, err)
		}
	})
}

func TestEnsureCertOnDiskRejectsRedactedKey(t *testing.T) {
	setupStorage(t)
	cert := &api.IssuedCert{SHA1: "ABCD", PEM: "cert", Key: "-----BEGIN REDACTED PRIVATE KEY-----\nKEY NOT FOUND\n-----END REDACTED PRIVATE KEY-----\n"}
	if _, err := EnsureCertOnDisk("cert1", cert); err == nil {
		t.Fatal("expected an error storing a redacted key")
	}
}

func TestEnsureMetadataIsSlim(t *testing.T) {
	setupStorage(t)
	cert := &api.IssuedCert{
		Id: 1, SHA1: "ABCD", SHA256: "sha256", SerialNumber: "01",
		PEM: "-----BEGIN CERTIFICATE-----", Chain: "chain", Key: "-----BEGIN PRIVATE KEY-----",
		IssueDate: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}

	// Old-style metadata for the same cert is rewritten.
	oldMeta, _ := json.MarshalIndent(map[string]any{"latestCert": cert}, "", "  ")
	writeFile(t, metadataPath("cert1"), oldMeta)

	updated, err := EnsureMetadata("cert1", cert)
	if err != nil || !updated {
		t.Fatalf("EnsureMetadata = %v, %v; want true, nil", updated, err)
	}
	data, _ := os.ReadFile(metadataPath("cert1"))
	if bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, []byte("CERTIFICATE")) {
		t.Fatalf("metadata.json still contains PEM data:\n%s", data)
	}

	var meta CertMetadata
	if err := json.Unmarshal(data, &meta); err != nil || meta.LatestCert.SHA1 != "ABCD" || meta.LatestCert.Id != 1 {
		t.Fatalf("unexpected metadata %s (err %v)", data, err)
	}

	updated, err = EnsureMetadata("cert1", cert)
	if err != nil || updated {
		t.Fatalf("second EnsureMetadata = %v, %v; want false, nil", updated, err)
	}
}

func TestSaveAndAdoptCSRKey(t *testing.T) {
	dir, key := setupStorage(t)
	csrPEM, keyPEM, err := keystoreCrypto.GenerateCSR([]string{"example.com"}, keystoreCrypto.KeyAlgorithmRSA2048)
	if err != nil {
		t.Fatal(err)
	}

	if err := SaveCSR("cert1", csrPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	assertEncryptedWith(t, filepath.Join(dir, "cert1", "csr", "key.pem"), key, []byte(keyPEM))
	if !HasPendingCSR("cert1") {
		t.Fatal("HasPendingCSR = false after SaveCSR")
	}

	cert := &api.IssuedCert{SHA1: "ABCD", PEM: selfSignedCertPEM(t, []byte(keyPEM))}
	matched, err := MatchAndAdoptCSRKey("cert1", cert)
	if err != nil || !matched {
		t.Fatalf("MatchAndAdoptCSRKey = %v, %v; want true, nil", matched, err)
	}
	assertEncryptedWith(t, filepath.Join(dir, "cert1", "abcd", "key.pem"), key, []byte(keyPEM))
	if HasPendingCSR("cert1") {
		t.Fatal("csr directory was not removed")
	}
}
