package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/certkit-io/certkit-keystore/auth"
	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
)

// ErrSigningRequestGone means CertKit no longer wants a signing result: the
// request was answered already or cancelled.
var ErrSigningRequestGone = errors.New("signing request is no longer pending (404)")

type SigningRequestType string

var SigningRequestTypes = struct {
	CreateCA         SigningRequestType
	RotateCA         SigningRequestType
	CreateCSR        SigningRequestType
	IssueCertificate SigningRequestType
	SignCRL          SigningRequestType
}{
	CreateCA:         "create_ca",
	RotateCA:         "rotate_ca",
	CreateCSR:        "create_csr",
	IssueCertificate: "issue_certificate",
	SignCRL:          "sign_crl",
}

// SigningRequest asks the keystore to use a private CA key it holds, or to
// create one. CertKit builds the whole certificate profile; the keystore
// generates keys and signs.
type SigningRequest struct {
	Id   int64              `json:"id"`
	Type SigningRequestType `json:"type"`
	// KeyAlgorithm is the algorithm for keys the keystore generates
	// (create_ca, rotate_ca, create_csr).
	KeyAlgorithm keystoreCrypto.KeyAlgorithm `json:"keyAlgorithm"`
	// SignerCaId is the CA whose stored key signs (rotate_ca: the root;
	// issue_certificate and sign_crl: the issuing CA), and SignerCertificate
	// its certificate.
	SignerCaId        string `json:"signerCaId"`
	SignerCertificate string `json:"signerCertificate"`
	// Root and Issuing are the CA certificates to create (create_ca; Issuing
	// is nil for a root-only CA). rotate_ca uses Issuing only.
	Root    *CertTemplate `json:"root"`
	Issuing *CertTemplate `json:"issuing"`
	// Certificate is the end-entity certificate to issue (issue_certificate).
	Certificate *CertTemplate `json:"certificate"`
	// Csr is the CSR to create for a subordinate CA key (create_csr).
	Csr *CsrTemplate `json:"csr"`
	// Crl is the revocation list to sign (sign_crl).
	Crl *CrlTemplate `json:"crl"`
}

type CertTemplate struct {
	// CaId is the CA whose key to create; CA templates only.
	CaId string `json:"caId"`
	// Subject is a base64 DER Name.
	Subject string `json:"subject"`
	// SerialNumber is hex.
	SerialNumber string    `json:"serialNumber"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	// PublicKey is a base64 DER SubjectPublicKeyInfo; issue_certificate only.
	PublicKey string `json:"publicKey"`
	// Extensions are copied into the certificate as they are. They never
	// include the subject or authority key identifier, which the keystore
	// derives from the keys.
	Extensions []CertExtension `json:"extensions"`
}

type CertExtension struct {
	Oid      string `json:"oid"`
	Critical bool   `json:"critical"`
	// Value is the base64 DER extnValue.
	Value string `json:"value"`
}

type CsrTemplate struct {
	CaId       string          `json:"caId"`
	Subject    string          `json:"subject"`
	Extensions []CertExtension `json:"extensions"`
}

type CrlTemplate struct {
	Number        int64         `json:"number"`
	ValidityHours int           `json:"validityHours"`
	Revoked       []RevokedCert `json:"revoked"`
}

type RevokedCert struct {
	// SerialNumber is hex.
	SerialNumber   string    `json:"serialNumber"`
	RevocationDate time.Time `json:"revocationDate"`
	// Reason is the CRLReason code; 0 (unspecified) is left out of the CRL.
	Reason int `json:"reason"`
}

// SigningResult answers a SigningRequest. Only the fields for the request's
// type are set; on failure only Error is.
type SigningResult struct {
	RequestId          int64  `json:"requestId"`
	Error              string `json:"error,omitempty"`
	RootCertificate    string `json:"rootCertificate,omitempty"`
	IssuingCertificate string `json:"issuingCertificate,omitempty"`
	Csr                string `json:"csr,omitempty"`
	Certificate        string `json:"certificate,omitempty"`
	// Crl is base64 DER.
	Crl string `json:"crl,omitempty"`
}

func SendSigningResult(result SigningResult) error {
	cfg := &config.CurrentConfig
	v := config.CurrentVersion

	priv, err := cfg.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}

	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal signing-result request: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") +
		"/api/keystore/v2/" + cfg.Keystore.Id + "/signing-result"

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if err := auth.SignRequest(httpReq, cfg.Keystore.Id, v.Version, priv, time.Now()); err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrSigningRequestGone
	default:
		return fmt.Errorf("signing-result failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}
}
