package privateca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
	"github.com/certkit-io/certkit-keystore/storage"
)

// setup points storage at a temp directory with a fresh encryption key.
func setup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := config.CurrentConfig
	t.Cleanup(func() { config.CurrentConfig = prev })
	config.CurrentConfig = config.Config{Keystore: &config.KeystoreInfo{StorageDir: dir}}

	key := make([]byte, keystoreCrypto.EncryptionKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetEncryptionKey(key); err != nil {
		t.Fatal(err)
	}
	return dir
}

// profile encodes the extensions Go puts in a certificate made from tmpl,
// the way CertKit sends them: everything but the key identifiers.
func profile(t *testing.T, tmpl *x509.Certificate) []api.CertExtension {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(1)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	var exts []api.CertExtension
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidSubjectKeyId) || e.Id.Equal(oidAuthorityKeyId) {
			continue
		}
		exts = append(exts, api.CertExtension{Oid: e.Id.String(), Critical: e.Critical, Value: base64.StdEncoding.EncodeToString(e.Value)})
	}
	return exts
}

func caProfile(t *testing.T, maxPathLen int) []api.CertExtension {
	return profile(t, &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLen == 0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	})
}

func leafProfile(t *testing.T) []api.CertExtension {
	return profile(t, &x509.Certificate{
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"www.example.com"},
	})
}

func subject(t *testing.T, cn string) string {
	t.Helper()
	der, err := asn1.Marshal(pkix.Name{CommonName: cn, Organization: []string{"Example"}}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func template(t *testing.T, caId, cn, serial string, exts []api.CertExtension) *api.CertTemplate {
	now := time.Now().Truncate(time.Second)
	return &api.CertTemplate{
		CaId:         caId,
		Subject:      subject(t, cn),
		SerialNumber: serial,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		Extensions:   exts,
	}
}

func parseCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("not a PEM certificate: %q", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// keyIdOf is RFC 5280 method 1, computed independently of subjectKeyId.
func keyIdOf(t *testing.T, spkiDER []byte) []byte {
	t.Helper()
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:]
}

func mustSign(t *testing.T, req api.SigningRequest) api.SigningResult {
	t.Helper()
	result := Sign(req)
	if result.Error != "" {
		t.Fatalf("%s request failed: %s", req.Type, result.Error)
	}
	if result.RequestId != req.Id {
		t.Fatalf("RequestId = %d, want %d", result.RequestId, req.Id)
	}
	return result
}

func signError(t *testing.T, req api.SigningRequest, want string) {
	t.Helper()
	result := Sign(req)
	if !strings.Contains(result.Error, want) {
		t.Fatalf("Error = %q, want it to contain %q", result.Error, want)
	}
	if result.RootCertificate != "" || result.IssuingCertificate != "" || result.Certificate != "" || result.Csr != "" || result.Crl != "" {
		t.Fatalf("a failed request returned a result: %+v", result)
	}
}

func createCARequest(t *testing.T, alg keystoreCrypto.KeyAlgorithm, withIssuing bool) api.SigningRequest {
	req := api.SigningRequest{
		Id:           1,
		Type:         api.SigningRequestTypes.CreateCA,
		KeyAlgorithm: alg,
		Root:         template(t, "root1", "Example Root CA", "01", caProfile(t, 1)),
	}
	if withIssuing {
		req.Issuing = template(t, "issuing1", "Example Issuing CA", "02", caProfile(t, 0))
	}
	return req
}

func TestCreateCA(t *testing.T) {
	dir := setup(t)
	result := mustSign(t, createCARequest(t, keystoreCrypto.KeyAlgorithmEC384, true))

	root := parseCert(t, result.RootCertificate)
	issuing := parseCert(t, result.IssuingCertificate)

	if !root.IsCA || root.MaxPathLen != 1 || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("root profile not applied: IsCA %v, MaxPathLen %d, KeyUsage %v", root.IsCA, root.MaxPathLen, root.KeyUsage)
	}
	if root.Subject.CommonName != "Example Root CA" || root.SerialNumber.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("root subject %q serial %s", root.Subject.CommonName, root.SerialNumber)
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Errorf("root is not self-signed: %v", err)
	}
	if !bytes.Equal(root.SubjectKeyId, keyIdOf(t, root.RawSubjectPublicKeyInfo)) {
		t.Error("root subject key identifier is not the SHA-1 of its key")
	}
	if root.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("root signature algorithm = %v, want ECDSA-SHA384", root.SignatureAlgorithm)
	}

	if !issuing.IsCA || issuing.MaxPathLen != 0 || !issuing.MaxPathLenZero {
		t.Errorf("issuing profile not applied: IsCA %v, MaxPathLen %d", issuing.IsCA, issuing.MaxPathLen)
	}
	if err := issuing.CheckSignatureFrom(root); err != nil {
		t.Errorf("issuing CA is not signed by the root: %v", err)
	}
	if !bytes.Equal(issuing.AuthorityKeyId, root.SubjectKeyId) {
		t.Error("issuing authority key identifier is not the root's subject key identifier")
	}
	if !bytes.Equal(issuing.SubjectKeyId, keyIdOf(t, issuing.RawSubjectPublicKeyInfo)) {
		t.Error("issuing subject key identifier is not the SHA-1 of its key")
	}

	// Both keys are stored encrypted, with their certificates.
	for _, caId := range []string{"root1", "issuing1"} {
		key, err := os.ReadFile(filepath.Join(dir, "private-cas", caId, "key.pem"))
		if err != nil {
			t.Fatalf("no key for %s: %v", caId, err)
		}
		if _, encrypted := keystoreCrypto.EncryptedKeyID(key); !encrypted {
			t.Errorf("key for %s is not encrypted at rest", caId)
		}
		if _, err := os.Stat(filepath.Join(dir, "private-cas", caId, "cert.pem")); err != nil {
			t.Errorf("no cert.pem for %s: %v", caId, err)
		}
	}
}

func TestCreateRootOnlyCA(t *testing.T) {
	setup(t)
	result := mustSign(t, createCARequest(t, keystoreCrypto.KeyAlgorithmRSA2048, false))

	root := parseCert(t, result.RootCertificate)
	if !root.IsCA || root.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("root IsCA %v, signature algorithm %v", root.IsCA, root.SignatureAlgorithm)
	}
	if result.IssuingCertificate != "" {
		t.Error("a root-only CA returned an issuing certificate")
	}
}

func TestCreateCAReusesKeys(t *testing.T) {
	dir := setup(t)
	req := createCARequest(t, keystoreCrypto.KeyAlgorithmEC256, true)
	first := mustSign(t, req)
	keyPath := filepath.Join(dir, "private-cas", "root1", "key.pem")
	keyBefore, _ := os.ReadFile(keyPath)

	// The same request again, as when its result didn't reach CertKit.
	second := mustSign(t, req)

	if keyAfter, _ := os.ReadFile(keyPath); !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("the stored root key was replaced")
	}
	for _, pair := range [][2]string{{first.RootCertificate, second.RootCertificate}, {first.IssuingCertificate, second.IssuingCertificate}} {
		a, b := parseCert(t, pair[0]), parseCert(t, pair[1])
		if !bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo) {
			t.Fatal("a repeated request generated a new key")
		}
	}

	// A different algorithm for an existing CA is refused, not swapped in.
	req.KeyAlgorithm = keystoreCrypto.KeyAlgorithmEC384
	signError(t, req, "already has a EC256 key")
}

func TestRotateCA(t *testing.T) {
	setup(t)
	root := parseCert(t, mustSign(t, createCARequest(t, keystoreCrypto.KeyAlgorithmEC256, false)).RootCertificate)

	result := mustSign(t, api.SigningRequest{
		Id:                2,
		Type:              api.SigningRequestTypes.RotateCA,
		KeyAlgorithm:      keystoreCrypto.KeyAlgorithmEC256,
		SignerCaId:        "root1",
		SignerCertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})),
		Issuing:           template(t, "issuing2", "Example Issuing CA 2", "03", caProfile(t, 0)),
	})

	issuing := parseCert(t, result.IssuingCertificate)
	if err := issuing.CheckSignatureFrom(root); err != nil {
		t.Fatalf("new issuing CA is not signed by the root: %v", err)
	}
	if !issuing.IsCA || result.RootCertificate != "" {
		t.Errorf("IsCA %v, root returned %v", issuing.IsCA, result.RootCertificate != "")
	}
}

func TestCreateCSR(t *testing.T) {
	dir := setup(t)
	result := mustSign(t, api.SigningRequest{
		Id:           3,
		Type:         api.SigningRequestTypes.CreateCSR,
		KeyAlgorithm: keystoreCrypto.KeyAlgorithmEC384,
		Csr: &api.CsrTemplate{
			CaId:       "sub1",
			Subject:    subject(t, "Example Subordinate CA"),
			Extensions: caProfile(t, 0),
		},
	})

	block, _ := pem.Decode([]byte(result.Csr))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("not a PEM CSR: %q", result.Csr)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	if csr.Subject.CommonName != "Example Subordinate CA" || keystoreCrypto.KeyAlgorithmOf(csr.PublicKey) != keystoreCrypto.KeyAlgorithmEC384 {
		t.Errorf("CSR subject %q, key %v", csr.Subject.CommonName, keystoreCrypto.KeyAlgorithmOf(csr.PublicKey))
	}

	var keyId, basicConstraints []byte
	for _, e := range csr.Extensions {
		switch {
		case e.Id.Equal(oidSubjectKeyId):
			if _, err := asn1.Unmarshal(e.Value, &keyId); err != nil {
				t.Fatal(err)
			}
		case e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}):
			basicConstraints = e.Value
		}
	}
	if !bytes.Equal(keyId, keyIdOf(t, csr.RawSubjectPublicKeyInfo)) {
		t.Error("the CSR's subject key identifier is not the SHA-1 of its key")
	}
	if basicConstraints == nil {
		t.Error("the template's basic constraints are not in the CSR")
	}

	for _, name := range []string{"key.pem", "csr.pem"} {
		if _, err := os.Stat(filepath.Join(dir, "private-cas", "sub1", name)); err != nil {
			t.Errorf("no %s for the subordinate CA: %v", name, err)
		}
	}
}

// issuingCA creates a root and issuing CA and returns the issuing CA's
// certificate (as PEM and parsed) and the root.
func issuingCA(t *testing.T) (issuingPEM string, issuing, root *x509.Certificate) {
	t.Helper()
	result := mustSign(t, createCARequest(t, keystoreCrypto.KeyAlgorithmEC256, true))
	return result.IssuingCertificate, parseCert(t, result.IssuingCertificate), parseCert(t, result.RootCertificate)
}

func leafRequest(t *testing.T, issuingPEM string, exts []api.CertExtension) api.SigningRequest {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf := template(t, "", "www.example.com", "0a1b2c3d", exts)
	leaf.PublicKey = base64.StdEncoding.EncodeToString(spki)
	return api.SigningRequest{
		Id:                4,
		Type:              api.SigningRequestTypes.IssueCertificate,
		SignerCaId:        "issuing1",
		SignerCertificate: issuingPEM,
		Certificate:       leaf,
	}
}

func TestIssueCertificate(t *testing.T) {
	setup(t)
	issuingPEM, issuing, root := issuingCA(t)
	req := leafRequest(t, issuingPEM, leafProfile(t))

	leaf := parseCert(t, mustSign(t, req).Certificate)

	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(issuing)
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       "www.example.com",
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not chain to the root: %v", err)
	}
	if spki, _ := base64.StdEncoding.DecodeString(req.Certificate.PublicKey); !bytes.Equal(leaf.RawSubjectPublicKeyInfo, spki) {
		t.Error("the leaf does not have the requested public key")
	}
	if leaf.IsCA || leaf.SerialNumber.Text(16) != "a1b2c3d" {
		t.Errorf("leaf IsCA %v, serial %s", leaf.IsCA, leaf.SerialNumber.Text(16))
	}
	if !bytes.Equal(leaf.AuthorityKeyId, issuing.SubjectKeyId) {
		t.Error("leaf authority key identifier is not the issuing CA's subject key identifier")
	}
}

func TestIssueCertificateRefusesCA(t *testing.T) {
	setup(t)
	issuingPEM, _, _ := issuingCA(t)
	signError(t, leafRequest(t, issuingPEM, caProfile(t, 0)), "refusing to issue a CA certificate")
}

func TestCATemplateMustMakeCA(t *testing.T) {
	setup(t)
	req := createCARequest(t, keystoreCrypto.KeyAlgorithmEC256, false)
	req.Root.Extensions = leafProfile(t)
	signError(t, req, "does not produce a CA certificate")
}

func TestTemplateMustNotCarryKeyIdentifiers(t *testing.T) {
	setup(t)
	req := createCARequest(t, keystoreCrypto.KeyAlgorithmEC256, false)
	req.Root.Extensions = append(req.Root.Extensions, api.CertExtension{Oid: "2.5.29.14", Value: base64.StdEncoding.EncodeToString([]byte{4, 1, 0})})
	signError(t, req, "must not be in the template")
}

func TestSignerKeyMissing(t *testing.T) {
	setup(t)
	issuingPEM, _, _ := issuingCA(t)
	req := leafRequest(t, issuingPEM, leafProfile(t))
	req.SignerCaId = "other"
	signError(t, req, "this keystore does not hold the key for CA other")
}

func TestSignerKeyMismatch(t *testing.T) {
	setup(t)
	_, _, root := issuingCA(t)
	// The issuing CA's key, with the root's certificate.
	req := leafRequest(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})), leafProfile(t))
	signError(t, req, "does not match the CA's certificate")
}

func TestSignCRL(t *testing.T) {
	setup(t)
	issuingPEM, issuing, _ := issuingCA(t)
	revokedAt := time.Now().Add(-2 * time.Hour).Truncate(time.Second).UTC()

	result := mustSign(t, api.SigningRequest{
		Id:                5,
		Type:              api.SigningRequestTypes.SignCRL,
		SignerCaId:        "issuing1",
		SignerCertificate: issuingPEM,
		Crl: &api.CrlTemplate{
			Number:        42,
			ValidityHours: 168,
			Revoked: []api.RevokedCert{
				{SerialNumber: "0a1b", RevocationDate: revokedAt, Reason: 4},
				{SerialNumber: "ff", RevocationDate: revokedAt, Reason: 0},
			},
		},
	})

	der, err := base64.StdEncoding.DecodeString(result.Crl)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(issuing); err != nil {
		t.Fatalf("CRL is not signed by the issuing CA: %v", err)
	}
	if crl.Number.Int64() != 42 || crl.NextUpdate.Sub(crl.ThisUpdate) != 168*time.Hour {
		t.Errorf("CRL number %s, validity %s", crl.Number, crl.NextUpdate.Sub(crl.ThisUpdate))
	}
	if !bytes.Equal(crl.AuthorityKeyId, issuing.SubjectKeyId) {
		t.Error("CRL authority key identifier is not the issuing CA's subject key identifier")
	}
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("%d revoked entries, want 2", len(crl.RevokedCertificateEntries))
	}
	first := crl.RevokedCertificateEntries[0]
	if first.SerialNumber.Text(16) != "a1b" || first.ReasonCode != 4 || !first.RevocationTime.Equal(revokedAt) {
		t.Errorf("first entry = serial %s, reason %d, time %s", first.SerialNumber.Text(16), first.ReasonCode, first.RevocationTime)
	}
}

func TestUnsupportedRequestType(t *testing.T) {
	setup(t)
	signError(t, api.SigningRequest{Id: 6, Type: "make_coffee"}, "unsupported signing request type")
}
