package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateCAKeysAreStoredKeys(t *testing.T) {
	t.Run("plaintext keys are encrypted at startup", func(t *testing.T) {
		dir, key := setupStorage(t)
		plain := newKeyPEM(t)
		keyPath := filepath.Join(dir, "private-cas", "ca1", "key.pem")
		writeFile(t, keyPath, plain)
		writeFile(t, filepath.Join(dir, "private-cas", "ca1", "cert.pem"), []byte("cert"))

		if res := MigrateToEncrypted(); res.Encrypted != 1 || len(res.Failed) != 0 {
			t.Fatalf("MigrateToEncrypted = %+v, want one key encrypted", res)
		}
		assertEncryptedWith(t, keyPath, key, plain)

		got, err := ReadPrivateCAKey("ca1")
		if err != nil || string(got) != string(plain) {
			t.Fatalf("ReadPrivateCAKey: %v", err)
		}
	})

	t.Run("a key from another registration starts over", func(t *testing.T) {
		dir, _ := setupStorage(t)
		writeFile(t, filepath.Join(dir, "private-cas", "ca1", "key.pem"), encryptWith(t, randomKey(t), newKeyPEM(t)))

		aside, err := StartOverIfUnreadable()
		if err != nil || aside == "" {
			t.Fatalf("StartOverIfUnreadable = %q, %v; want the directory moved", aside, err)
		}
		t.Cleanup(func() { os.RemoveAll(aside) })
	})

	t.Run("not a certificate stored before v2", func(t *testing.T) {
		dir, _ := setupStorage(t)
		writeFile(t, filepath.Join(dir, "private-cas", "ca1", "key.pem"), newKeyPEM(t))

		if certs, err := ListStoredCerts(); err != nil || len(certs) != 0 {
			t.Fatalf("ListStoredCerts = %v, %v; want none", certs, err)
		}
		if moved, err := AdoptLegacyCert("col1", "private-cas"); err != nil || moved {
			t.Fatalf("AdoptLegacyCert(private-cas) = %v, %v; want false, nil", moved, err)
		}
		if !exists(filepath.Join(dir, "private-cas", "ca1", "key.pem")) {
			t.Fatal("the private CA directory was moved")
		}
	})
}

func TestSavePrivateCAKey(t *testing.T) {
	dir, key := setupStorage(t)
	first := newKeyPEM(t)

	if _, err := ReadPrivateCAKey("ca1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadPrivateCAKey before saving = %v, want os.ErrNotExist", err)
	}
	if err := SavePrivateCAKey("ca1", first); err != nil {
		t.Fatal(err)
	}
	assertEncryptedWith(t, filepath.Join(dir, "private-cas", "ca1", "key.pem"), key, first)

	// A CA key is never replaced.
	if err := SavePrivateCAKey("ca1", newKeyPEM(t)); err == nil {
		t.Fatal("an existing CA key was replaced")
	}
	assertEncryptedWith(t, filepath.Join(dir, "private-cas", "ca1", "key.pem"), key, first)

	for _, bad := range []string{"", "..", "../ca"} {
		if err := SavePrivateCAKey(bad, first); err == nil || !strings.Contains(err.Error(), "invalid CA ID") {
			t.Errorf("SavePrivateCAKey(%q) = %v, want an invalid CA ID error", bad, err)
		}
	}
}

func TestListPrivateCAs(t *testing.T) {
	setupStorage(t)
	if err := SavePrivateCAKey("ca1", newKeyPEM(t)); err != nil {
		t.Fatal(err)
	}
	if err := SavePrivateCACertificate("ca1", "cert"); err != nil {
		t.Fatal(err)
	}
	if err := SavePrivateCACSR("ca2", "csr"); err != nil {
		t.Fatal(err)
	}

	cas, err := ListPrivateCAs()
	if err != nil || len(cas) != 2 {
		t.Fatalf("ListPrivateCAs = %+v, %v; want two", cas, err)
	}
	for _, ca := range cas {
		switch ca.Id {
		case "ca1":
			if !ca.KeyStored || !ca.KeyEncrypted || string(ca.CertPEM) != "cert" {
				t.Errorf("ca1 = %+v", ca)
			}
		case "ca2":
			if ca.KeyStored || string(ca.CSRPEM) != "csr" {
				t.Errorf("ca2 = %+v", ca)
			}
		default:
			t.Errorf("unexpected CA %q", ca.Id)
		}
	}
}
