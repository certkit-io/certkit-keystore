package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/certkit-io/certkit-keystore/api"
	"github.com/certkit-io/certkit-keystore/config"
	"github.com/certkit-io/certkit-keystore/storage"
	"github.com/certkit-io/certkit-keystore/utils"
)

// --- poll state ---

// pollState is what the status page knows about the poll loop. Its slices and
// map are replaced on every poll, never modified, so copies can share them.
type pollState struct {
	LastAttempt time.Time
	LastSuccess time.Time
	Err         error
	// Collections are the collections CertKit sent in the last successful
	// poll, in its order, and Statuses what the keystore reported for each of
	// their certificates, by certificate ID.
	Collections   []pollCollection
	Statuses      map[string]api.UpdateStatusItem
	UpdateVersion string
}

type pollCollection struct {
	Id      string
	Name    string
	CertIds []string
}

var (
	pollMu    sync.Mutex
	lastPoll  pollState
	startedAt = time.Now()
)

// RecordPoll notes a successful poll: the certificates CertKit sent and the
// status reported for each.
func RecordPoll(resp *api.PollResponse, statuses []api.UpdateStatusItem) {
	collections := make([]pollCollection, 0, len(resp.Collections))
	for _, c := range resp.Collections {
		ids := make([]string, 0, len(c.Certificates))
		for _, cert := range c.Certificates {
			ids = append(ids, cert.CustomCertId)
		}
		collections = append(collections, pollCollection{Id: c.Id, Name: c.Name, CertIds: ids})
	}
	byId := make(map[string]api.UpdateStatusItem, len(statuses))
	for _, s := range statuses {
		byId[s.CustomCertId] = s
	}
	update := ""
	if u := resp.UpdateAvailable; u != nil && u.Version != config.CurrentVersion.Version {
		update = u.Version
	}

	now := time.Now()
	pollMu.Lock()
	defer pollMu.Unlock()
	lastPoll = pollState{LastAttempt: now, LastSuccess: now, Collections: collections, Statuses: byId, UpdateVersion: update}
}

// RecordPollFailure notes a failed poll. What the last successful poll
// reported is kept.
func RecordPollFailure(err error) {
	pollMu.Lock()
	defer pollMu.Unlock()
	lastPoll.LastAttempt = time.Now()
	lastPoll.Err = err
}

func currentPoll() pollState {
	pollMu.Lock()
	defer pollMu.Unlock()
	return lastPoll
}

// --- page model ---

//go:embed status_page.html
var statusPageHTML string

var statusPageTemplate = template.Must(template.New("status").Parse(statusPageHTML))

// Classes used by the page: "good", "ok" and "bad" color a value green, amber
// and red; "" leaves it neutral.

type statusPage struct {
	Version       config.VersionInfo
	CertkitURL    string
	ManagementURL string
	Port          string
	Uptime        string
	Health        health
	LastCheck     string
	PollError     string
	Unauthorized  bool
	UpdateVersion string
	Keystore      section
	Groups        []certGroup
	PrivateCAs    []caRow
	// Sections come after the certificates.
	Sections  []section
	Generated string
}

// certGroup is one box of certificates: a collection CertKit sent, or the
// stored certificates it didn't. Empty is shown when there are none.
type certGroup struct {
	Title string
	URL   string
	Certs []certRow
	Empty string
}

type health struct {
	Message string
	Class   string
}

type certRow struct {
	Name        string
	OtherNames  string
	AllNames    string
	ID          string
	URL         string
	SHA1        string
	Versions    int
	Status      string
	StatusClass string
	Pending     bool
	Message     string
	Expires     *when
	Key         string
	KeyNote     string
	KeyClass    string
}

// caRow is a private CA whose key the keystore holds for CertKit.
type caRow struct {
	Name     string
	ID       string
	URL      string
	Kind     string
	Expires  *when
	Key      string
	KeyNote  string
	KeyClass string
}

type when struct {
	Date     string
	Exact    string
	Relative string
	Class    string
}

type section struct {
	Title string
	// Notes explain the section, above its fields.
	Notes  []sectionNote
	Fields []field
}

// sectionNote is a sentence or two that starts with Term in bold.
type sectionNote struct {
	Term string
	Text string
}

// field is one row of a section. Note is muted text after the value; Title
// is the value's tooltip.
type field struct {
	Label string
	Value string
	Note  string
	Class string
	Title string
	Link  string
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	if err := statusPageTemplate.Execute(&buf, buildStatusPage(time.Now())); err != nil {
		log.Printf("Failed to render status page: %v", err)
		http.Error(w, "failed to render status page", http.StatusInternalServerError)
		return
	}
	writeHTML(w, http.StatusOK, buf.Bytes(), "'self'")
}

// writeHTML sends one of the keystore's pages. Pages run no scripts and load
// nothing but CertKit's logo and Google's fonts; formAction is where their
// forms may go.
func writeHTML(w http.ResponseWriter, status int, page []byte, formAction string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; img-src "+certkitOrigin()+
		"; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com"+
		"; base-uri 'none'; form-action "+formAction+"; frame-ancestors 'none'")
	w.WriteHeader(status)
	w.Write(page)
}

func certkitBaseURL() string {
	return strings.TrimRight(config.CurrentConfig.CertkitBaseUrl, "/")
}

// certkitOrigin is where the page's logo and favicon come from.
func certkitOrigin() string {
	u, err := url.Parse(config.CurrentConfig.CertkitBaseUrl)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "https:"
	}
	return u.Scheme + "://" + u.Host
}

func buildStatusPage(now time.Time) statusPage {
	cfg := &config.CurrentConfig
	poll := currentPoll()

	stored, err := storage.ListStoredCerts()
	if err != nil {
		log.Printf("Status page: failed to list storage directory: %v", err)
	}
	groups := certGroups(poll, stored, now)

	page := statusPage{
		Version:       config.CurrentVersion,
		CertkitURL:    certkitBaseURL(),
		ManagementURL: certkitBaseURL() + "/settings/keystore",
		Port:          cfg.Keystore.Port,
		Uptime:        formatUptime(now.Sub(startedAt)),
		Health:        pageHealth(poll, groups),
		UpdateVersion: poll.UpdateVersion,
		Groups:        groups,
		PrivateCAs:    privateCARows(now),
		Generated:     formatTime(now),
	}
	if !poll.LastAttempt.IsZero() {
		page.LastCheck = relativeTime(poll.LastAttempt, now)
	}
	if poll.Err != nil {
		page.PollError = poll.Err.Error()
		page.Unauthorized = errors.Is(poll.Err, api.ErrKeystoreUnauthorized)
	}

	page.Keystore = keystoreSection(poll, now)
	page.Sections = []section{
		trustSection(now),
		hostSection(now),
	}
	return page
}

func pageHealth(poll pollState, groups []certGroup) health {
	switch {
	case errors.Is(poll.Err, api.ErrKeystoreUnauthorized):
		return health{"Not authorized in CertKit", "bad"}
	case poll.Err != nil:
		return health{"Can't check in with CertKit", "bad"}
	case poll.LastAttempt.IsZero():
		return health{"Connecting to CertKit", "ok"}
	}

	bad := 0
	for _, g := range groups {
		for _, c := range g.Certs {
			if c.StatusClass == "bad" {
				bad++
			}
		}
	}
	switch {
	case bad == 1:
		return health{"1 certificate needs attention", "bad"}
	case bad > 1:
		return health{plural(bad, "certificate") + " need attention", "bad"}
	}
	return health{"Running", "good"}
}

// --- certificates ---

// certGroups lists the collections CertKit sent in the last poll with their
// certificates, then any other certificates in the storage directory.
func certGroups(poll pollState, stored []storage.StoredCert, now time.Time) []certGroup {
	type location struct{ collectionId, certId string }
	byLocation := make(map[location]storage.StoredCert, len(stored))
	for _, sc := range stored {
		byLocation[location{sc.CollectionId, sc.CustomCertId}] = sc
	}
	shown := make(map[location]bool, len(stored))

	var groups []certGroup
	for _, c := range poll.Collections {
		group := certGroup{
			Title: c.Name,
			URL:   certkitBaseURL() + "/app/" + c.Id + "/keystore",
			Empty: "No certificates in this collection yet.",
		}
		if group.Title == "" {
			group.Title = c.Id
		}
		for _, id := range c.CertIds {
			// Look where storage.ReadLatestCert does: the collection
			// directory, then where keystores before v2 stored it.
			loc := location{c.Id, id}
			sc, ok := byLocation[loc]
			if !ok {
				loc = location{"", id}
				sc, ok = byLocation[loc]
			}
			if ok {
				shown[loc] = true
			} else {
				sc = storage.StoredCert{CustomCertId: id}
			}

			row := certRowFor(c.Id, sc, now)
			if s, ok := poll.Statuses[id]; ok {
				row.Status, row.StatusClass, row.Pending = statusLabel(s.Status)
				if row.StatusClass == "bad" {
					row.Message = s.Message
				}
			} else {
				row.Status, row.StatusClass = "Not Issued", "ok"
			}
			group.Certs = append(group.Certs, row)
		}
		groups = append(groups, group)
	}

	other := certGroup{Title: "Other Stored Certificates"}
	for _, sc := range stored {
		if shown[location{sc.CollectionId, sc.CustomCertId}] {
			continue
		}
		row := certRowFor(sc.CollectionId, sc, now)
		if poll.LastSuccess.IsZero() {
			row.Status = "Waiting for CertKit"
		} else {
			row.Status = "Not in CertKit"
			row.Message = "CertKit no longer sends this certificate to the keystore."
		}
		other.Certs = append(other.Certs, row)
	}

	if poll.LastSuccess.IsZero() {
		// Which collections the keystore serves isn't known until CertKit answers.
		other.Title = "Certificate Storage"
		other.Empty = "No certificates yet. Certificates you assign to this keystore in CertKit will show up here."
		return []certGroup{other}
	}
	if len(groups) == 0 {
		groups = append(groups, certGroup{
			Title: "Certificate Storage",
			Empty: "No collections use this keystore yet. Collections you add to the keystore in CertKit will show up here.",
		})
	}
	if len(other.Certs) > 0 {
		groups = append(groups, other)
	}
	return groups
}

// privateCARows lists the private CA keys in the storage directory, named and
// dated from the CA's certificate (or, before it has one, its CSR).
func privateCARows(now time.Time) []caRow {
	cas, err := storage.ListPrivateCAs()
	if err != nil {
		log.Printf("Status page: failed to list private CAs: %v", err)
	}

	var rows []caRow
	for _, ca := range cas {
		row := caRow{Name: ca.Id, ID: ca.Id, URL: certkitBaseURL() + "/settings/certificate-authorities/" + ca.Id}
		var pub any
		if cert, err := parseCertPEM(ca.CertPEM); err == nil {
			if cert.Subject.CommonName != "" {
				row.Name = cert.Subject.CommonName
			}
			pub = cert.PublicKey
			row.Expires = expiry(cert.NotAfter, now)
			row.Kind = "issuing CA"
			if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
				row.Kind = "root CA"
			}
		} else if csr, err := parseCSRPEM(ca.CSRPEM); err == nil {
			if csr.Subject.CommonName != "" {
				row.Name = csr.Subject.CommonName
			}
			pub = csr.PublicKey
			row.Kind = "awaiting certificate"
		}

		switch {
		case !ca.KeyStored:
			row.Key, row.KeyClass = "Missing", "bad"
		case ca.KeyEncrypted:
			row.Key, row.KeyNote = keyAlgorithm(pub), "encrypted at rest"
		default:
			row.Key, row.KeyNote, row.KeyClass = keyAlgorithm(pub), "not encrypted", "ok"
		}
		rows = append(rows, row)
	}
	return rows
}

func statusLabel(status api.CertStatus) (label, class string, pending bool) {
	switch status {
	case api.CertStatuses.Synced:
		return "Stored", "good", false
	case api.CertStatuses.PendingCSR:
		return "Pending Certificate Request", "good", true
	case api.CertStatuses.KeyNotFound:
		return "Private Key Missing", "bad", false
	case api.CertStatuses.CertNotStored:
		return "Not Stored", "bad", false
	default:
		return "Error", "bad", false
	}
}

// certRowFor describes a stored certificate. collectionId is the collection
// it belongs to, or "" if unknown (stored before v2 and not sent by CertKit).
func certRowFor(collectionId string, sc storage.StoredCert, now time.Time) certRow {
	row := certRow{
		Name:     sc.CustomCertId,
		ID:       sc.CustomCertId,
		Versions: sc.Versions,
	}
	if collectionId != "" {
		row.URL = certkitBaseURL() + "/app/" + collectionId + "/certificates/" + sc.CustomCertId
	}
	if sc.Latest != nil {
		row.SHA1 = strings.ToUpper(sc.Latest.SHA1)
	}

	var names []string
	var pub any
	if cert, err := parseCertPEM(sc.CertPEM); err == nil {
		names = displayNames(cert.Subject.CommonName, sanNames(cert))
		pub = cert.PublicKey
		row.Expires = expiry(cert.NotAfter, now)
	} else if csr, err := parseCSRPEM(sc.CSRPEM); err == nil {
		names = displayNames(csr.Subject.CommonName, csr.DNSNames)
	}
	if len(names) > 0 {
		row.Name = names[0]
		row.AllNames = strings.Join(names, ", ")
		row.OtherNames = summarizeNames(names[1:], 3)
	}

	switch {
	case sc.Latest != nil && !sc.KeyStored:
		row.Key, row.KeyClass = "Missing", "bad"
	case sc.Latest != nil:
		row.Key = keyAlgorithm(pub)
		if sc.KeyEncrypted {
			row.KeyNote = "encrypted at rest"
		} else {
			row.KeyNote, row.KeyClass = "not encrypted", "ok"
		}
	case len(sc.CSRPEM) > 0:
		row.Key, row.KeyNote = "Generated", "awaiting certificate"
	}
	return row
}

// displayNames names a certificate by its SANs, the hostnames it secures. The
// common name is only a fallback: it can be any text, and short-lived
// profiles leave it out.
func displayNames(commonName string, sans []string) []string {
	if names := dedupe(sans); len(names) > 0 {
		return names
	}
	return dedupe([]string{commonName})
}

func sanNames(cert *x509.Certificate) []string {
	names := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}

func dedupe(names []string) []string {
	seen := make(map[string]bool, len(names))
	var out []string
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func summarizeNames(names []string, max int) string {
	if len(names) <= max {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s +%d more", strings.Join(names[:max], ", "), len(names)-max)
}

func keyAlgorithm(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "Stored"
	}
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseCSRPEM(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// --- detail sections ---

func keystoreSection(poll pollState, now time.Time) section {
	k := config.CurrentConfig.Keystore

	check := field{Label: "Checked in", Value: "Not yet"}
	if !poll.LastAttempt.IsZero() {
		check.Value, check.Title = relativeTime(poll.LastAttempt, now), formatTime(poll.LastAttempt)
		check.Class, check.Note = "good", "every 30s"
		if poll.Err != nil {
			check.Class, check.Note = "bad", "failed"
		}
	}
	s := section{Title: "Keystore", Fields: []field{check}}
	if poll.Err != nil {
		success := field{Label: "Last success", Value: "Never"}
		if !poll.LastSuccess.IsZero() {
			success.Value, success.Title = relativeTime(poll.LastSuccess, now), formatTime(poll.LastSuccess)
		}
		s.Fields = append(s.Fields, success)
	}

	enc := field{Label: "Encryption", Value: "Key not loaded", Class: "bad"}
	if kid := storage.EncryptionKeyID(); kid != "" {
		enc = field{Label: "Encryption", Value: "On", Class: "good", Note: "key " + kid,
			Title: "Private keys are encrypted at rest with a key held by CertKit and kept in memory only"}
	}
	collections := field{Label: "Collections"}
	if !poll.LastSuccess.IsZero() {
		collections.Value = strconv.Itoa(len(poll.Collections))
	}

	s.Fields = append(s.Fields,
		field{Label: "Keystore Base URL", Value: k.BaseUrl()},
		field{Label: "CertKit Base URL", Value: certkitBaseURL(), Link: certkitBaseURL()},
		enc,
		collections,
		field{Label: "Port", Value: k.Port},
		field{Label: "Storage", Value: absPath(k.StorageDir)},
		field{Label: "Config", Value: absPath(config.CurrentPath)},
		field{Label: "Service", Value: k.ServiceName},
		field{Label: "Keystore ID", Value: k.Id},
	)
	return s
}

func trustSection(now time.Time) section {
	s := section{Title: "CA & TLS", Notes: []sectionNote{
		{"The CA", "is this keystore's own certificate authority, created when the keystore first started. " +
			"It isn't one of your private CAs in CertKit, and it signs nothing but the keystore's TLS certificate."},
		{"Agents", "trust the keystore through CertKit, which sends them this CA's certificate. " +
			"They only accept a keystore certificate that chains to it. " +
			"Browsers don't know the CA, which is why they warn about this page."},
		{"The TLS certificate", "is what the keystore serves on its HTTPS port. " +
			"It covers the host in the Keystore Base URL, the address agents connect to, " +
			"and renews itself " + approxDuration(rotationWindow) + " before it expires."},
	}}

	if ca, err := readCertFile(filepath.Join(caDir(), caCertFile)); err != nil {
		s.Fields = append(s.Fields, field{Label: "CA", Value: "Unreadable", Note: err.Error(), Class: "bad"})
	} else {
		s.Fields = append(s.Fields,
			expiryField("CA expires", ca.NotAfter, now),
			field{Label: "CA fingerprint", Value: fingerprint(ca.Raw), Note: "SHA-256"},
		)
	}

	if srv, err := readCertFile(filepath.Join(caDir(), serverCertFile)); err != nil {
		s.Fields = append(s.Fields, field{Label: "TLS cert", Value: "Unreadable", Note: err.Error(), Class: "bad"})
	} else {
		exp := expiryField("TLS expires", srv.NotAfter, now)
		exp.Note += ", auto-renews"
		s.Fields = append(s.Fields,
			field{Label: "TLS hosts", Value: strings.Join(sanNames(srv), ", ")},
			exp,
			field{Label: "Protocol", Value: "TLS 1.3"},
		)
	}
	return s
}

// hostType runs once: on Windows, detecting a VM shells out to PowerShell.
var hostType = sync.OnceValue(utils.DetectHostType)

func hostSection(now time.Time) section {
	v := config.CurrentVersion
	hostname, _ := os.Hostname()
	exe, _ := os.Executable()

	return section{Title: "Host", Fields: []field{
		{Label: "Hostname", Value: hostname},
		{Label: "Platform", Value: runtime.GOOS + "/" + runtime.GOARCH, Note: hostType()},
		{Label: "Timezone", Value: utils.FormatTimezone()},
		{Label: "Started", Value: relativeTime(startedAt, now), Title: formatTime(startedAt)},
		{Label: "Binary", Value: exe},
		{Label: "Version", Value: v.Version, Note: v.Commit, Title: "Built " + v.Date},
	}}
}

func readCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCertPEM(data)
}

func absPath(path string) string {
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// --- formatting ---

func expiry(t, now time.Time) *when {
	return &when{Date: formatDate(t), Exact: formatTime(t), Relative: relativeTime(t, now), Class: expiryClass(t, now)}
}

func expiryField(label string, t, now time.Time) field {
	e := expiry(t, now)
	return field{Label: label, Value: e.Date, Title: e.Exact, Note: e.Relative, Class: e.Class}
}

func expiryClass(t, now time.Time) string {
	switch left := t.Sub(now); {
	case left < 7*24*time.Hour:
		return "bad"
	case left < 14*24*time.Hour:
		return "ok"
	default:
		return "good"
	}
}

func formatDate(t time.Time) string {
	return t.Local().Format("Jan 2, 2006")
}

func formatTime(t time.Time) string {
	return t.Local().Format("Jan 2, 2006 15:04 MST")
}

// relativeTime describes t relative to now: "in 3 days", "5 minutes ago".
func relativeTime(t, now time.Time) string {
	d := t.Sub(now)
	switch {
	case d > -10*time.Second && d < 10*time.Second:
		return "just now"
	case d < 0:
		return approxDuration(-d) + " ago"
	default:
		return "in " + approxDuration(d)
	}
}

func approxDuration(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d < time.Minute:
		return plural(int(d.Seconds()), "second")
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute")
	case d < 2*day:
		return plural(int(d.Hours()), "hour")
	case d < 90*day:
		return plural(int(d/day), "day")
	case d < 2*365*day:
		return plural(int(d/(30*day)), "month")
	default:
		return plural(int(d/(365*day)), "year")
	}
}

func formatUptime(d time.Duration) string {
	d = d.Round(time.Minute)
	days, hours, minutes := int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	default:
		return fmt.Sprintf("%dm", minutes)
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
