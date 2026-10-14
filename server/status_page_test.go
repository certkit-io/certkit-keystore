package server

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certkit-io/certkit-keystore/api"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
	"github.com/certkit-io/certkit-keystore/storage"
)

// setupStatusPage gives the server package a storage directory with a CA, a
// server cert, and an encryption key, and resets the poll state afterwards.
func setupStatusPage(t *testing.T) {
	t.Helper()
	setupServer(t)
	setEncryptionKey(t)
	prevPoll := lastPoll
	t.Cleanup(func() { lastPoll = prevPoll })
	lastPoll = pollState{}

	if err := EnsureCA(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTLSManager(); err != nil {
		t.Fatal(err)
	}
}

// storeIssuedCert writes an issued cert for hosts, signed by the keystore CA,
// to storage under customCertId.
func storeIssuedCert(t *testing.T, customCertId string, hosts ...string) {
	t.Helper()
	caCert, err := os.ReadFile(filepath.Join(caDir(), caCertFile))
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := storage.ReadPrivateKey(filepath.Join(caDir(), caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := keystoreCrypto.IssueServerCert(string(caCert), string(caKey), hosts)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	sum := sha1.Sum(block.Bytes)

	issued := &api.IssuedCert{Id: 1, SHA1: hex.EncodeToString(sum[:]), PEM: certPEM, Key: keyPEM, IssueDate: time.Now()}
	if _, err := storage.EnsureCertOnDisk(customCertId, issued); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.EnsureMetadata(customCertId, issued); err != nil {
		t.Fatal(err)
	}
}

func getStatusPage(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	handleRoot(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func assertContains(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("page is missing %q", w)
		}
	}
}

func TestStatusPageShowsCertificates(t *testing.T) {
	setupStatusPage(t)

	storeIssuedCert(t, "stored", "www.example.com", "example.com")
	storeIssuedCert(t, "orphan", "old.example.com")
	csrPEM, keyPEM, err := keystoreCrypto.GenerateCSR([]string{"pending.example.com"}, keystoreCrypto.KeyAlgorithmEC256)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveCSR("pending", csrPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	RecordPoll(&api.PollResponse{Certificates: []api.PollCertificate{
		{CustomCertId: "stored"}, {CustomCertId: "pending"}, {CustomCertId: "missing"}, {CustomCertId: "unissued"},
	}}, []api.UpdateStatusItem{
		{CustomCertId: "stored", Status: api.CertStatuses.Synced},
		{CustomCertId: "pending", Status: api.CertStatuses.PendingCSR},
		{CustomCertId: "missing", Status: api.CertStatuses.KeyNotFound, Message: "key not found at <path>"},
	})

	body := getStatusPage(t)
	// The test certs' common name is "CertKit Keystore"; rows are named by SAN.
	if strings.Contains(body, ">CertKit Keystore</a>") {
		t.Error("certificate row is named by its common name instead of its first SAN")
	}
	assertContains(t, body,
		">www.example.com</a>", "Stored", "ECDSA P-256", "encrypted at rest",
		"pending.example.com", "Pending Certificate Request", "awaiting certificate",
		"Private Key Missing", "key not found at &lt;path&gt;",
		"Not Issued",
		"old.example.com", "Not in CertKit",
		"1 certificate needs attention",
		"CA expires", "keystore.example.com",
	)
}

func TestStatusPageShowsPollFailure(t *testing.T) {
	setupStatusPage(t)
	storeIssuedCert(t, "stored", "www.example.com")

	RecordPoll(&api.PollResponse{Certificates: []api.PollCertificate{{CustomCertId: "stored"}}},
		[]api.UpdateStatusItem{{CustomCertId: "stored", Status: api.CertStatuses.Synced}})
	RecordPollFailure(errors.New("dial tcp: connection refused"))

	body := getStatusPage(t)
	assertContains(t, body, "Can&#39;t check in with CertKit", "dial tcp: connection refused", "www.example.com", "Stored")

	RecordPollFailure(api.ErrKeystoreUnauthorized)
	assertContains(t, getStatusPage(t), "Not authorized in CertKit")
}

func TestStatusPageBeforeFirstPoll(t *testing.T) {
	setupStatusPage(t)
	storeIssuedCert(t, "stored", "www.example.com")

	assertContains(t, getStatusPage(t), "Connecting to CertKit", "Waiting for CertKit", "www.example.com")
}
