package server

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/certkit-io/certkit-keystore/api"
	"software.sslmate.com/src/go-pkcs12"
)

// validateAs makes CertKit's validation approve every request for the given
// certificate, whatever the request body names.
func validateAs(t *testing.T, collectionId, certificateId string) {
	t.Helper()
	prev := validateAgentRequest
	t.Cleanup(func() { validateAgentRequest = prev })
	validateAgentRequest = func(agentSqid string, agentReq api.AgentRequest) (*api.ValidateAgentResponse, error) {
		return &api.ValidateAgentResponse{Valid: true, CollectionId: collectionId, CertificateId: certificateId}, nil
	}
}

func fetchRequest(handler http.HandlerFunc, body string) *http.Response {
	req := httptest.NewRequest(http.MethodPost, "/api/agent/v1/agent1/fetch", strings.NewReader(body))
	req.SetPathValue("agentSqid", "agent1")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec.Result()
}

func TestFetchCertificateServesValidatedCert(t *testing.T) {
	setupStatusPage(t)
	sha1 := storeIssuedCert(t, "col1", "cert1", "one.example.com")
	storeIssuedCert(t, "col1", "cert2", "two.example.com")
	validateAs(t, "col1", "cert1")

	// The body asks for cert2; CertKit validated cert1.
	res := fetchRequest(handleFetchCertificate, `{"config_id":"cfg1","certificate_id":"cert2"}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	var body fetchCertificateResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.CertificateSha1 != sha1 {
		t.Fatalf("served certificate %s, want cert1 (%s)", body.CertificateSha1, sha1)
	}
	block, _ := pem.Decode([]byte(body.CertificatePem))
	if block == nil {
		t.Fatal("no certificate in the response")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !slices.Contains(cert.DNSNames, "one.example.com") {
		t.Fatalf("served %v (err %v), want one.example.com", cert.DNSNames, err)
	}
	if !strings.Contains(body.KeyPem, "PRIVATE KEY") || strings.Contains(body.KeyPem, "ENCRYPTED") {
		t.Fatal("the key is not served as plaintext PEM")
	}
}

func TestFetchPfxServesValidatedCert(t *testing.T) {
	setupStatusPage(t)
	storeIssuedCert(t, "col1", "cert1", "one.example.com")
	storeIssuedCert(t, "col1", "cert2", "two.example.com")
	validateAs(t, "col1", "cert1")

	res := fetchRequest(handleFetchPfx, `{"config_id":"cfg1","certificate_id":"cert2"}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	pfxData, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	_, cert, err := pkcs12.Decode(pfxData, res.Header.Get("X-Certkit-Pfx-Password"))
	if err != nil {
		t.Fatalf("decode PFX: %v", err)
	}
	if !slices.Contains(cert.DNSNames, "one.example.com") {
		t.Fatalf("served %v, want one.example.com", cert.DNSNames)
	}
}

func TestFetchCertificateRejectedByCertKit(t *testing.T) {
	setupStatusPage(t)
	storeIssuedCert(t, "col1", "cert1", "one.example.com")

	prev := validateAgentRequest
	t.Cleanup(func() { validateAgentRequest = prev })
	validateAgentRequest = func(string, api.AgentRequest) (*api.ValidateAgentResponse, error) {
		return nil, errors.New("agent request not valid")
	}

	res := fetchRequest(handleFetchCertificate, `{"config_id":"cfg1","certificate_id":"cert1"}`)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
}

func TestFetchCertificateNotStored(t *testing.T) {
	setupStatusPage(t)
	validateAs(t, "col1", "missing")

	res := fetchRequest(handleFetchCertificate, `{"config_id":"cfg1","certificate_id":"missing"}`)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
}
