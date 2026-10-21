// Package privateca carries out CertKit's private CA signing requests with
// keys only the keystore holds. CertKit builds each certificate profile and
// sends the extensions already encoded; this package generates keys, derives
// the key identifiers, and signs.
package privateca

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/certkit-io/certkit-keystore/api"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
	"github.com/certkit-io/certkit-keystore/storage"
)

var (
	oidSubjectKeyId   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyId = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// Sign carries out one signing request and returns the result to send back.
// Failures are reported in the result's Error.
func Sign(req api.SigningRequest) api.SigningResult {
	var result api.SigningResult
	var err error

	switch req.Type {
	case api.SigningRequestTypes.CreateCA:
		result, err = createCA(req)
	case api.SigningRequestTypes.RotateCA:
		result, err = rotateCA(req)
	case api.SigningRequestTypes.CreateCSR:
		result, err = createCSR(req)
	case api.SigningRequestTypes.IssueCertificate:
		result, err = issueCertificate(req)
	case api.SigningRequestTypes.SignCRL:
		result, err = signCRL(req)
	default:
		err = fmt.Errorf("unsupported signing request type %q", req.Type)
	}

	if err != nil {
		return api.SigningResult{RequestId: req.Id, Error: err.Error()}
	}
	result.RequestId = req.Id
	return result
}

// createCA creates a root CA and, unless the request is for a root-only CA,
// an issuing CA signed by the root.
func createCA(req api.SigningRequest) (api.SigningResult, error) {
	if req.Root == nil {
		return api.SigningResult{}, errors.New("the request has no root certificate template")
	}

	rootKey, err := caKey(req.Root.CaId, req.KeyAlgorithm)
	if err != nil {
		return api.SigningResult{}, err
	}
	rootTemplate, err := certificateTemplate(req.Root, rootKey.Public())
	if err != nil {
		return api.SigningResult{}, fmt.Errorf("root template: %w", err)
	}
	root, rootPEM, err := createCertificate(rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		return api.SigningResult{}, fmt.Errorf("create root certificate: %w", err)
	}
	if !root.IsCA {
		return api.SigningResult{}, errors.New("the root template does not produce a CA certificate")
	}
	saveCertificate(req.Root.CaId, rootPEM)

	result := api.SigningResult{RootCertificate: rootPEM}
	if req.Issuing == nil {
		return result, nil
	}

	issuingPEM, err := createIssuingCA(req.Issuing, req.KeyAlgorithm, root, rootKey)
	if err != nil {
		return api.SigningResult{}, err
	}
	result.IssuingCertificate = issuingPEM
	return result, nil
}

// rotateCA creates a new issuing CA under an existing root.
func rotateCA(req api.SigningRequest) (api.SigningResult, error) {
	if req.Issuing == nil {
		return api.SigningResult{}, errors.New("the request has no issuing certificate template")
	}

	rootKey, root, err := signer(req.SignerCaId, req.SignerCertificate)
	if err != nil {
		return api.SigningResult{}, err
	}
	issuingPEM, err := createIssuingCA(req.Issuing, req.KeyAlgorithm, root, rootKey)
	if err != nil {
		return api.SigningResult{}, err
	}
	return api.SigningResult{IssuingCertificate: issuingPEM}, nil
}

func createIssuingCA(t *api.CertTemplate, keyAlgorithm keystoreCrypto.KeyAlgorithm, root *x509.Certificate, rootKey crypto.Signer) (string, error) {
	key, err := caKey(t.CaId, keyAlgorithm)
	if err != nil {
		return "", err
	}
	template, err := certificateTemplate(t, key.Public())
	if err != nil {
		return "", fmt.Errorf("issuing template: %w", err)
	}
	cert, certPEM, err := createCertificate(template, root, key.Public(), rootKey)
	if err != nil {
		return "", fmt.Errorf("create issuing certificate: %w", err)
	}
	if !cert.IsCA {
		return "", errors.New("the issuing template does not produce a CA certificate")
	}
	saveCertificate(t.CaId, certPEM)
	return certPEM, nil
}

// createCSR creates the key for a subordinate CA whose certificate another CA
// issues (a bring-your-own root), and the CSR for it.
func createCSR(req api.SigningRequest) (api.SigningResult, error) {
	if req.Csr == nil {
		return api.SigningResult{}, errors.New("the request has no CSR template")
	}

	key, err := caKey(req.Csr.CaId, req.KeyAlgorithm)
	if err != nil {
		return api.SigningResult{}, err
	}
	subject, err := decodeSubject(req.Csr.Subject)
	if err != nil {
		return api.SigningResult{}, err
	}
	extensions, err := decodeExtensions(req.Csr.Extensions)
	if err != nil {
		return api.SigningResult{}, err
	}
	keyId, err := subjectKeyId(key.Public())
	if err != nil {
		return api.SigningResult{}, err
	}
	keyIdValue, err := asn1.Marshal(keyId)
	if err != nil {
		return api.SigningResult{}, fmt.Errorf("encode subject key identifier: %w", err)
	}
	extensions = append(extensions, pkix.Extension{Id: oidSubjectKeyId, Value: keyIdValue})

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		RawSubject:      subject,
		ExtraExtensions: extensions,
	}, key)
	if err != nil {
		return api.SigningResult{}, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	if err := storage.SavePrivateCACSR(req.Csr.CaId, csrPEM); err != nil {
		log.Printf("Failed to save CSR for CA %s: %v", req.Csr.CaId, err)
	}
	return api.SigningResult{Csr: csrPEM}, nil
}

// issueCertificate issues an end-entity certificate from an issuing CA.
func issueCertificate(req api.SigningRequest) (api.SigningResult, error) {
	if req.Certificate == nil {
		return api.SigningResult{}, errors.New("the request has no certificate template")
	}

	issuerKey, issuer, err := signer(req.SignerCaId, req.SignerCertificate)
	if err != nil {
		return api.SigningResult{}, err
	}
	spki, err := base64.StdEncoding.DecodeString(req.Certificate.PublicKey)
	if err != nil {
		return api.SigningResult{}, fmt.Errorf("decode public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return api.SigningResult{}, fmt.Errorf("parse public key: %w", err)
	}
	template, err := certificateTemplate(req.Certificate, pub)
	if err != nil {
		return api.SigningResult{}, fmt.Errorf("certificate template: %w", err)
	}
	cert, certPEM, err := createCertificate(template, issuer, pub, issuerKey)
	if err != nil {
		return api.SigningResult{}, fmt.Errorf("create certificate: %w", err)
	}
	if cert.IsCA {
		return api.SigningResult{}, errors.New("refusing to issue a CA certificate as an end-entity certificate")
	}
	return api.SigningResult{Certificate: certPEM}, nil
}

// signCRL signs a CA's certificate revocation list.
func signCRL(req api.SigningRequest) (api.SigningResult, error) {
	if req.Crl == nil {
		return api.SigningResult{}, errors.New("the request has no CRL template")
	}
	if req.Crl.ValidityHours <= 0 {
		return api.SigningResult{}, fmt.Errorf("invalid CRL validity of %d hours", req.Crl.ValidityHours)
	}

	issuerKey, issuer, err := signer(req.SignerCaId, req.SignerCertificate)
	if err != nil {
		return api.SigningResult{}, err
	}
	if len(issuer.SubjectKeyId) == 0 {
		return api.SigningResult{}, fmt.Errorf("the certificate of CA %s has no subject key identifier, which a CRL needs", req.SignerCaId)
	}

	var entries []x509.RevocationListEntry
	for _, revoked := range req.Crl.Revoked {
		serial, err := parseSerialNumber(revoked.SerialNumber)
		if err != nil {
			return api.SigningResult{}, err
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: revoked.RevocationDate,
			ReasonCode:     revoked.Reason,
		})
	}

	now := time.Now()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(req.Crl.Number),
		ThisUpdate:                now,
		NextUpdate:                now.Add(time.Duration(req.Crl.ValidityHours) * time.Hour),
		RevokedCertificateEntries: entries,
	}, issuer, issuerKey)
	if err != nil {
		return api.SigningResult{}, fmt.Errorf("create CRL: %w", err)
	}
	return api.SigningResult{Crl: base64.StdEncoding.EncodeToString(crlDER)}, nil
}

// caKey returns the key of a CA the keystore creates, generating and storing
// it first if it doesn't exist yet. A request is sent again when its result
// didn't reach CertKit, so the key from the first attempt is reused.
func caKey(caId string, keyAlgorithm keystoreCrypto.KeyAlgorithm) (crypto.Signer, error) {
	keyPEM, err := storage.ReadPrivateCAKey(caId)
	if err == nil {
		key, err := keystoreCrypto.ParsePrivateKeyPEM(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("read key for CA %s: %w", caId, err)
		}
		if existing := keystoreCrypto.KeyAlgorithmOf(key.Public()); existing != keyAlgorithm {
			return nil, fmt.Errorf("CA %s already has a %s key, not %s", caId, existing, keyAlgorithm)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read key for CA %s: %w", caId, err)
	}

	key, err := keystoreCrypto.GeneratePrivateKey(keyAlgorithm)
	if err != nil {
		return nil, err
	}
	keyPEM, err = keystoreCrypto.EncodePrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	// The key is stored before anything is signed with it.
	if err := storage.SavePrivateCAKey(caId, keyPEM); err != nil {
		return nil, fmt.Errorf("save key for CA %s: %w", caId, err)
	}
	log.Printf("Created %s key for private CA %s", keyAlgorithm, caId)
	return key, nil
}

// signer returns the stored key of an existing CA and its certificate, after
// checking that they belong together.
func signer(caId string, certPEM string) (crypto.Signer, *x509.Certificate, error) {
	if caId == "" {
		return nil, nil, errors.New("the request does not say which CA signs")
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("no certificate for CA %s in the request", caId)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate of CA %s: %w", caId, err)
	}

	keyPEM, err := storage.ReadPrivateCAKey(caId)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("this keystore does not hold the key for CA %s", caId)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read key for CA %s: %w", caId, err)
	}
	key, err := keystoreCrypto.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("read key for CA %s: %w", caId, err)
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, nil, fmt.Errorf("the key this keystore holds for CA %s does not match the CA's certificate", caId)
	}

	saveCertificate(caId, string(pem.EncodeToMemory(block)))
	return key, cert, nil
}

func certificateTemplate(t *api.CertTemplate, pub crypto.PublicKey) (*x509.Certificate, error) {
	subject, err := decodeSubject(t.Subject)
	if err != nil {
		return nil, err
	}
	serial, err := parseSerialNumber(t.SerialNumber)
	if err != nil {
		return nil, err
	}
	extensions, err := decodeExtensions(t.Extensions)
	if err != nil {
		return nil, err
	}
	keyId, err := subjectKeyId(pub)
	if err != nil {
		return nil, err
	}

	// Everything else in the profile (key usage, basic constraints, names,
	// ...) is in the extensions. Go adds the authority key identifier from
	// the issuer's subject key identifier.
	return &x509.Certificate{
		RawSubject:      subject,
		SerialNumber:    serial,
		NotBefore:       t.NotBefore,
		NotAfter:        t.NotAfter,
		ExtraExtensions: extensions,
		SubjectKeyId:    keyId,
	}, nil
}

// createCertificate signs template with signerKey. Go picks the signature
// algorithm from the key: ECDSA with SHA-256 for P-256, SHA-384 for P-384,
// and SHA-256 with RSA, as CertKit's own profiles do.
func createCertificate(template, parent *x509.Certificate, pub crypto.PublicKey, signerKey crypto.Signer) (*x509.Certificate, string, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signerKey)
	if err != nil {
		return nil, "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, "", fmt.Errorf("parse the new certificate: %w", err)
	}
	return cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// subjectKeyId is the SHA-1 of the subjectPublicKey bits (RFC 5280 4.2.1.2,
// method 1).
func subjectKeyId(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:], nil
}

func decodeSubject(encoded string) ([]byte, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode subject: %w", err)
	}
	var name pkix.RDNSequence
	if rest, err := asn1.Unmarshal(der, &name); err != nil || len(rest) > 0 {
		return nil, errors.New("the subject is not a DER-encoded name")
	}
	return der, nil
}

func decodeExtensions(in []api.CertExtension) ([]pkix.Extension, error) {
	var out []pkix.Extension
	for _, e := range in {
		oid, err := parseOID(e.Oid)
		if err != nil {
			return nil, err
		}
		if oid.Equal(oidSubjectKeyId) || oid.Equal(oidAuthorityKeyId) {
			return nil, fmt.Errorf("extension %s must not be in the template: the keystore derives key identifiers from the keys", e.Oid)
		}
		value, err := base64.StdEncoding.DecodeString(e.Value)
		if err != nil {
			return nil, fmt.Errorf("decode extension %s: %w", e.Oid, err)
		}
		out = append(out, pkix.Extension{Id: oid, Critical: e.Critical, Value: value})
	}
	return out, nil
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid extension OID %q", s)
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid extension OID %q", s)
		}
		oid[i] = n
	}
	return oid, nil
}

func parseSerialNumber(hex string) (*big.Int, error) {
	serial, ok := new(big.Int).SetString(hex, 16)
	if !ok || serial.Sign() <= 0 {
		return nil, fmt.Errorf("invalid serial number %q", hex)
	}
	return serial, nil
}

// saveCertificate keeps a CA's certificate next to its key for the status
// page. That is a convenience, so a failure is only logged.
func saveCertificate(caId string, certPEM string) {
	if err := storage.SavePrivateCACertificate(caId, certPEM); err != nil {
		log.Printf("Failed to save certificate for CA %s: %v", caId, err)
	}
}
