//go:build windows

package selfupdate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const signedFixture = "testdata/ev-signed-file.exe"

func TestAuthenticodeSignerValid(t *testing.T) {
	cert, err := authenticodeSigner(signedFixture)
	if err != nil {
		t.Fatalf("authenticodeSigner: %v", err)
	}
	if cert.Subject.CommonName != "WireGuard LLC" {
		t.Fatalf("signer = %q, want WireGuard LLC", cert.Subject)
	}
}

func TestAuthenticodeSignerTampered(t *testing.T) {
	b, err := os.ReadFile(signedFixture)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2-1]++
	path := filepath.Join(t.TempDir(), "tampered.exe")
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticodeSigner(path); err == nil {
		t.Fatal("tampered binary verified")
	}
}

func TestAuthenticodeSignerUnsigned(t *testing.T) {
	// The test binary itself is never signed.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticodeSigner(exe); err == nil {
		t.Fatal("unsigned binary verified")
	}
}

func TestVerifyUpdateSignatureRequiresSignedRunningBinary(t *testing.T) {
	err := verifyUpdateSignature(signedFixture)
	if err == nil || !strings.Contains(err.Error(), "running binary is not validly signed") {
		t.Fatalf("err = %v, want refusal because the running binary is unsigned", err)
	}
}

func TestCheckSamePublisher(t *testing.T) {
	signed, err := authenticodeSigner(signedFixture)
	if err != nil {
		t.Fatalf("authenticodeSigner: %v", err)
	}
	if err := checkSamePublisher(signed, signed); err != nil {
		t.Fatalf("same publisher rejected: %v", err)
	}

	other := &x509.Certificate{Subject: pkix.Name{
		CommonName:   "TrackJS LLC",
		Organization: []string{"TrackJS LLC"},
		Locality:     []string{"Minneapolis"},
		Province:     []string{"Minnesota"},
		Country:      []string{"US"},
	}}
	if err := checkSamePublisher(other, signed); err == nil {
		t.Fatal("different publisher accepted")
	}
}
