package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// storeCert writes a complete issued certificate (plaintext key) to the
// certificate directory root, and returns its cert.pem.
func storeCert(t *testing.T, root string) string {
	t.Helper()
	keyPEM := newKeyPEM(t)
	certPEM := selfSignedCertPEM(t, keyPEM)
	data, err := marshalMetadata(CertMetadata{LatestCert: &CertInfo{Id: 1, SHA1: "ABCD", IssueDate: time.Now()}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, metadataPath(root), data)
	writeFile(t, filepath.Join(issuedCertDir(root, "ABCD"), "cert.pem"), []byte(certPEM))
	writeFile(t, filepath.Join(issuedCertDir(root, "ABCD"), "key.pem"), keyPEM)
	return certPEM
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestAdoptLegacyCert(t *testing.T) {
	t.Run("moves a certificate into its collection", func(t *testing.T) {
		dir, _ := setupStorage(t)
		certPEM := storeCert(t, filepath.Join(dir, "cert1"))
		writeFile(t, filepath.Join(dir, "cert1", "csr", "key.pem"), newKeyPEM(t))

		moved, err := AdoptLegacyCert("col1", "cert1")
		if err != nil || !moved {
			t.Fatalf("AdoptLegacyCert = %v, %v; want true, nil", moved, err)
		}
		if exists(filepath.Join(dir, "cert1")) {
			t.Error("the old directory is still there")
		}
		for _, rel := range []string{"metadata.json", "abcd/cert.pem", "abcd/key.pem", "csr/key.pem"} {
			if !exists(filepath.Join(dir, "collections", "col1", "cert1", rel)) {
				t.Errorf("%s was not moved", rel)
			}
		}
		files, err := ReadLatestCert("col1", "cert1")
		if err != nil || files.CertPEM != certPEM {
			t.Fatalf("ReadLatestCert after the move: %v", err)
		}

		// Nothing is left to move.
		if moved, err := AdoptLegacyCert("col1", "cert1"); err != nil || moved {
			t.Fatalf("second AdoptLegacyCert = %v, %v; want false, nil", moved, err)
		}
	})

	t.Run("nothing to move", func(t *testing.T) {
		dir, _ := setupStorage(t)
		if moved, err := AdoptLegacyCert("col1", "cert1"); err != nil || moved {
			t.Fatalf("AdoptLegacyCert = %v, %v; want false, nil", moved, err)
		}
		if exists(filepath.Join(dir, "collections")) {
			t.Error("a collection directory was created with nothing to move")
		}
	})

	t.Run("both locations are left alone", func(t *testing.T) {
		dir, _ := setupStorage(t)
		legacyCert := storeCert(t, filepath.Join(dir, "cert1"))
		currentCert := storeCert(t, certRootDir("col1", "cert1"))

		if moved, err := AdoptLegacyCert("col1", "cert1"); err != nil || moved {
			t.Fatalf("AdoptLegacyCert = %v, %v; want false, nil", moved, err)
		}
		if !exists(filepath.Join(dir, "cert1", "metadata.json")) {
			t.Error("the old directory was removed")
		}
		files, err := ReadLatestCert("col1", "cert1")
		if err != nil || files.CertPEM != currentCert || files.CertPEM == legacyCert {
			t.Fatalf("ReadLatestCert did not use the collection directory: %v", err)
		}
	})

	t.Run("keystore directories and unsafe IDs are never moved", func(t *testing.T) {
		dir, _ := setupStorage(t)
		writeFile(t, filepath.Join(dir, "ca", "ca-cert.pem"), []byte("ca"))
		storeCert(t, filepath.Join(dir, "cert1"))

		for _, ids := range [][2]string{{"col1", "ca"}, {"col1", "collections"}, {"..", "cert1"}, {"col1", "../cert1"}, {"", "cert1"}} {
			if moved, err := AdoptLegacyCert(ids[0], ids[1]); err != nil || moved {
				t.Errorf("AdoptLegacyCert(%q, %q) = %v, %v; want false, nil", ids[0], ids[1], moved, err)
			}
		}
		if !exists(filepath.Join(dir, "ca", "ca-cert.pem")) || !exists(filepath.Join(dir, "cert1", "metadata.json")) {
			t.Error("a directory was moved")
		}
	})
}

func TestReadLatestCertFallsBackToLegacyDirectory(t *testing.T) {
	dir, _ := setupStorage(t)
	legacyCert := storeCert(t, filepath.Join(dir, "cert1"))

	files, err := ReadLatestCert("col1", "cert1")
	if err != nil || files.CertPEM != legacyCert || files.SHA1 != "ABCD" {
		t.Fatalf("ReadLatestCert = %v; want the certificate stored before v2", err)
	}

	if _, err := ReadLatestCert("col1", "missing"); err == nil {
		t.Error("ReadLatestCert found a certificate that isn't stored")
	}
	if _, err := ReadLatestCert("..", "cert1"); err == nil {
		t.Error("ReadLatestCert accepted an unsafe collection ID")
	}
}

func TestListStoredCertsBothLayouts(t *testing.T) {
	dir, _ := setupStorage(t)
	storeCert(t, certRootDir("col1", "cert1"))
	csrPEM, keyPEM := "-----BEGIN CERTIFICATE REQUEST-----", string(newKeyPEM(t))
	if err := SaveCSR("col2", "cert2", csrPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	storeCert(t, filepath.Join(dir, "cert3"))
	writeFile(t, filepath.Join(dir, "ca", "ca-cert.pem"), []byte("ca"))
	writeFile(t, filepath.Join(dir, ".certkit-healthcheck"), []byte("x"))
	writeFile(t, filepath.Join(dir, "collections", "stray-file"), []byte("x"))

	certs, err := ListStoredCerts()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]StoredCert{}
	for _, sc := range certs {
		got[sc.CollectionId+"/"+sc.CustomCertId] = sc
	}
	if len(certs) != 3 {
		t.Fatalf("ListStoredCerts = %v, want col1/cert1, col2/cert2 and /cert3", got)
	}
	if sc, ok := got["col1/cert1"]; !ok || sc.Latest == nil || !sc.KeyStored || len(sc.CertPEM) == 0 {
		t.Errorf("col1/cert1 = %+v", sc)
	}
	if sc, ok := got["col2/cert2"]; !ok || string(sc.CSRPEM) != csrPEM {
		t.Errorf("col2/cert2 = %+v", sc)
	}
	if sc, ok := got["/cert3"]; !ok || sc.Latest == nil {
		t.Errorf("cert3 stored before v2 = %+v", sc)
	}
}

func TestIsSafeId(t *testing.T) {
	for _, id := range []string{"x7k2", "5xkt", "abc-DEF_123"} {
		if !IsSafeId(id) {
			t.Errorf("IsSafeId(%q) = false", id)
		}
	}
	for _, id := range []string{"", ".", "..", "../ca", `a\b`, "a/b", "a b", "ä"} {
		if IsSafeId(id) {
			t.Errorf("IsSafeId(%q) = true", id)
		}
	}
}
