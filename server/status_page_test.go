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
	"github.com/certkit-io/certkit-keystore/config"
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
// to storage under collectionId and customCertId, and returns its SHA1.
func storeIssuedCert(t *testing.T, collectionId string, customCertId string, hosts ...string) string {
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
	if _, err := storage.EnsureCertOnDisk(collectionId, customCertId, issued); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.EnsureMetadata(collectionId, customCertId, issued); err != nil {
		t.Fatal(err)
	}
	return issued.SHA1
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

	storeIssuedCert(t, "col1", "stored", "www.example.com", "example.com")
	storeIssuedCert(t, "col2", "orphan", "old.example.com")
	csrPEM, keyPEM, err := keystoreCrypto.GenerateCSR([]string{"pending.example.com"}, keystoreCrypto.KeyAlgorithmEC256)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveCSR("col1", "pending", csrPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	RecordPoll(&api.PollResponse{Collections: []api.PollCollection{{Id: "col1", Name: "Production", Certificates: []api.PollCertificate{
		{CustomCertId: "stored"}, {CustomCertId: "pending"}, {CustomCertId: "missing"}, {CustomCertId: "unissued"},
	}}}}, []api.UpdateStatusItem{
		{CollectionId: "col1", CustomCertId: "stored", Status: api.CertStatuses.Synced},
		{CollectionId: "col1", CustomCertId: "pending", Status: api.CertStatuses.PendingCSR},
		{CollectionId: "col1", CustomCertId: "missing", Status: api.CertStatuses.KeyNotFound, Message: "key not found at <path>"},
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
		"old.example.com", "Not in CertKit", "Other Stored Certificates",
		"1 certificate needs attention",
		"CA expires", "keystore.example.com",
		">Production</a>", "/app/col1/keystore", "/app/col1/certificates/stored", "/app/col2/certificates/orphan",
		"/settings/keystore",
	)
}

func TestStatusPageGroupsCollections(t *testing.T) {
	setupStatusPage(t)

	storeIssuedCert(t, "col1", "first", "first.example.com")
	// Stored before v2, directly under the storage directory, and not moved
	// into its collection yet.
	storeIssuedCert(t, "col2", "legacy", "legacy.example.com")
	storageDir := config.CurrentConfig.Keystore.StorageDir
	if err := os.Rename(filepath.Join(storageDir, "collections", "col2", "legacy"), filepath.Join(storageDir, "legacy")); err != nil {
		t.Fatal(err)
	}

	RecordPoll(&api.PollResponse{Collections: []api.PollCollection{
		{Id: "col1", Name: "Production", Certificates: []api.PollCertificate{{CustomCertId: "first"}}},
		{Id: "col2", Name: "Staging", Certificates: []api.PollCertificate{{CustomCertId: "legacy"}}},
		{Id: "col3", Name: "Empty", Certificates: nil},
	}}, []api.UpdateStatusItem{
		{CollectionId: "col1", CustomCertId: "first", Status: api.CertStatuses.Synced},
		{CollectionId: "col2", CustomCertId: "legacy", Status: api.CertStatuses.Synced},
	})

	body := getStatusPage(t)
	assertContains(t, body,
		">Production</a>", ">Staging</a>", ">Empty</a>",
		"first.example.com", "/app/col1/certificates/first",
		"legacy.example.com", "/app/col2/certificates/legacy",
		"No certificates in this collection yet.",
		"Running",
	)
	if strings.Contains(body, "Other Stored Certificates") {
		t.Error("a certificate CertKit sent is listed as not sent")
	}
	if strings.Index(body, "Production") > strings.Index(body, "Staging") {
		t.Error("collections are not in CertKit's order")
	}
}

func TestStatusPageLayout(t *testing.T) {
	setupStatusPage(t)
	storeIssuedCert(t, "col1", "first", "first.example.com")
	RecordPoll(&api.PollResponse{Collections: []api.PollCollection{
		{Id: "col1", Name: "Production", Certificates: []api.PollCertificate{{CustomCertId: "first"}}},
	}}, []api.UpdateStatusItem{
		{CollectionId: "col1", CustomCertId: "first", Status: api.CertStatuses.Synced},
	})

	body := getStatusPage(t)

	// The keystore block comes first, then the certificates, then the details.
	last := -1
	for _, s := range []string{"<h2>Keystore</h2>", ">Production</a>", "<h2>CA &amp; TLS</h2>", "<h2>Host</h2>"} {
		i := strings.Index(body, s)
		if i < 0 {
			t.Fatalf("page is missing %q", s)
		}
		if i < last {
			t.Fatalf("%q is out of order", s)
		}
		last = i
	}

	// The keystore block starts with the check-in, and the two base URLs
	// are next to each other.
	keystore := body[strings.Index(body, "<h2>Keystore</h2>"):strings.Index(body, ">Production</a>")]
	if !strings.HasPrefix(keystore[strings.Index(keystore, "<dt>"):], "<dt>Checked in</dt>") {
		t.Error("the keystore block doesn't start with the check-in")
	}
	urls := keystore[strings.Index(keystore, "<dt>Keystore Base URL</dt>"):]
	if next := strings.Index(urls[1:], "<dt>"); !strings.HasPrefix(urls[1+next:], "<dt>CertKit Base URL</dt>") {
		t.Error("the CertKit base URL isn't right under the keystore base URL")
	}
	for _, gone := range []string{"<dt>Account</dt>", "<dt>Assigned</dt>", "<h2>CertKit</h2>"} {
		if strings.Contains(body, gone) {
			t.Errorf("page still has %q", gone)
		}
	}

	ca, err := readCertFile(filepath.Join(caDir(), caCertFile))
	if err != nil {
		t.Fatal(err)
	}
	assertContains(t, body, fingerprint(ca.Raw), "<strong>Agents</strong>", "renews itself 30 days before it expires")
}

func TestStatusPageHasAShowLogsButton(t *testing.T) {
	setupStatusPage(t)
	assertContains(t, getStatusPage(t), `<a class="button" href="/logs">Show logs</a>`)
}

func TestStatusPageShowsPrivateCAs(t *testing.T) {
	setupStatusPage(t)
	certPEM, keyPEM, err := keystoreCrypto.GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SavePrivateCAKey("ca1", []byte(keyPEM)); err != nil {
		t.Fatal(err)
	}
	if err := storage.SavePrivateCACertificate("ca1", certPEM); err != nil {
		t.Fatal(err)
	}
	RecordPoll(&api.PollResponse{}, nil)

	assertContains(t, getStatusPage(t),
		"Private CA Keys", "CertKit Keystore CA", "root CA &middot; ca1",
		"/settings/certificate-authorities/ca1", "ECDSA P-256", "encrypted at rest",
	)
}

func TestStatusPageWithNoCollections(t *testing.T) {
	setupStatusPage(t)
	storeIssuedCert(t, "col1", "stored", "www.example.com")

	RecordPoll(&api.PollResponse{}, nil)

	assertContains(t, getStatusPage(t),
		"No collections use this keystore yet.",
		"Other Stored Certificates", "www.example.com", "Not in CertKit",
	)
}

func TestStatusPageShowsPollFailure(t *testing.T) {
	setupStatusPage(t)
	storeIssuedCert(t, "col1", "stored", "www.example.com")

	RecordPoll(&api.PollResponse{Collections: []api.PollCollection{{Id: "col1", Name: "Production", Certificates: []api.PollCertificate{{CustomCertId: "stored"}}}}},
		[]api.UpdateStatusItem{{CollectionId: "col1", CustomCertId: "stored", Status: api.CertStatuses.Synced}})
	RecordPollFailure(errors.New("dial tcp: connection refused"))

	body := getStatusPage(t)
	assertContains(t, body, "Can&#39;t check in with CertKit", "dial tcp: connection refused", "www.example.com", "Stored")

	RecordPollFailure(api.ErrKeystoreUnauthorized)
	assertContains(t, getStatusPage(t), "Not authorized in CertKit")
}

func TestStatusPageBeforeFirstPoll(t *testing.T) {
	setupStatusPage(t)
	storeIssuedCert(t, "col1", "stored", "www.example.com")

	assertContains(t, getStatusPage(t), "Connecting to CertKit", "Certificate Storage", "Waiting for CertKit", "www.example.com")
}
