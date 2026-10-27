package server

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/certkit-io/certkit-keystore/config"
)

const sampleLog = `2026/10/26 23:59:58 certkit-keystore v2.0.0 (commit: abc123, built: 2026-10-26)
2026/10/26 23:59:59 Poll failed: dial tcp 10.0.0.1:443: connect: connection refused
2026/10/27 00:00:01 Ran command: netsh advfirewall firewall add rule:
Ok.

2026/10/27 00:00:02 Waiting for encryption key from CertKit: status=503 (retrying in 5s)
2026/10/27 00:00:03 Agent 4kd8 requesting cert abc (config c1, collection col1)
2026/10/27 00:00:04 Status page: <script>alert(1)</script> logged in
`

// setupLogs gives the keystore a log file with content, as on Windows, and
// makes local time UTC. It returns the log file's path.
func setupLogs(t *testing.T, content string) string {
	t.Helper()
	setupLogSource(t, false)
	path := filepath.Join(t.TempDir(), "certkit-keystore.log")
	config.CurrentLogPath = path
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// setupJournal has the keystore read its log from journald, as on Linux,
// where journalctl prints output or fails with err. It returns the arguments
// of each journalctl run.
func setupJournal(t *testing.T, output string, err error) *[][]string {
	t.Helper()
	setupLogSource(t, true)
	runs := [][]string{}
	journalctl = func(args ...string) ([]byte, error) {
		runs = append(runs, args)
		return []byte(output), err
	}
	return &runs
}

func setupLogSource(t *testing.T, journal bool) {
	t.Helper()
	prevConfig, prevLogPath, prevJournal, prevJournalctl, prevLocal :=
		config.CurrentConfig, config.CurrentLogPath, useJournal, journalctl, time.Local
	t.Cleanup(func() {
		config.CurrentConfig = prevConfig
		config.CurrentLogPath = prevLogPath
		useJournal = prevJournal
		journalctl = prevJournalctl
		time.Local = prevLocal
	})

	config.CurrentConfig = config.Config{
		CertkitBaseUrl: "https://app.certkit.test/",
		Keystore:       &config.KeystoreInfo{Id: "ks1", Host: "keystore.example.com", Port: "443"},
	}
	useJournal = journal
	time.Local = time.UTC
}

// journalLine is a line of journalctl's JSON output.
func journalLine(at time.Time, identifier, message string) string {
	return fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%d","SYSLOG_IDENTIFIER":%q,"MESSAGE":%q}`+"\n", at.UnixMicro(), identifier, message)
}

func getLogsPage(t *testing.T, target string) string {
	t.Helper()
	res := browse(handleLogs, http.MethodGet, target)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	// The search and logout forms.
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") {
		t.Fatalf("Content-Security-Policy = %q, want it to allow the page's forms", csp)
	}
	return responseBody(t, res)
}

func assertInOrder(t *testing.T, body string, want ...string) {
	t.Helper()
	last := -1
	for _, w := range want {
		i := strings.Index(body, w)
		if i < 0 {
			t.Fatalf("page is missing %q", w)
		}
		if i < last {
			t.Fatalf("%q is out of order", w)
		}
		last = i
	}
}

func TestLogsPageShowsTheNewestEntriesFirst(t *testing.T) {
	setupLogs(t, sampleLog)

	body := getLogsPage(t, "/logs")
	assertInOrder(t, body,
		"Tuesday, Oct 27, 2026", "Status page:", "Agent 4kd8", "Waiting for encryption key", "Ran command",
		"Monday, Oct 26, 2026", "Poll failed", "certkit-keystore v2.0.0",
	)
	assertContains(t, body,
		`<li class="entry error"><time title="2026/10/26 23:59:59 UTC">23:59:59</time><span class="msg">Poll failed:`,
		`<li class="entry warning"><time title="2026/10/27 00:00:02 UTC">00:00:02</time>`,
		"Ran command: netsh advfirewall firewall add rule:\nOk.</span>",
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		`All<span class="n">6</span>`, `Problems<span class="n">2</span>`,
		`href="/logs/download"`, "newest first, times in UTC", "certkit-keystore.log",
	)
	if strings.Contains(body, "<script>") {
		t.Error("an entry wasn't escaped")
	}
}

func TestLogsPageSearches(t *testing.T) {
	setupLogs(t, sampleLog)

	body := getLogsPage(t, "/logs?q=AGENT")
	assertContains(t, body,
		"<mark>Agent</mark> 4kd8", `value="AGENT"`,
		`All<span class="n">1</span>`, `Problems<span class="n">0</span>`,
		// The tabs keep the search, and clearing it keeps the tab.
		`href="/logs?problems=1&amp;q=AGENT"`, `<a class="clear" href="/logs">Clear search</a>`,
	)
	if strings.Contains(body, "Poll failed") {
		t.Error("showed an entry that doesn't match")
	}

	assertContains(t, getLogsPage(t, "/logs?q=nothing+like+this"), "No entries match “nothing like this”.")
}

func TestLogsPageShowsProblems(t *testing.T) {
	setupLogs(t, sampleLog)

	body := getLogsPage(t, "/logs?problems=1")
	assertContains(t, body,
		"Poll failed", "Waiting for encryption key",
		`<a class="tab on" href="/logs?problems=1" aria-current="page">Problems`,
		// A search stays on the tab.
		`<input type="hidden" name="problems" value="1">`,
	)
	for _, s := range []string{"Agent 4kd8", "Ran command"} {
		if strings.Contains(body, s) {
			t.Errorf("showed %q, which isn't a problem", s)
		}
	}

	assertContains(t, getLogsPage(t, "/logs?problems=1&q=agent"), "No problems match “agent”.")
}

func TestLogsPageShowsTheNewestThousandEntries(t *testing.T) {
	var b strings.Builder
	start := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	for i := range 1005 {
		fmt.Fprintf(&b, "%s Entry %d\n", start.Add(time.Duration(i)*time.Second).Format(logTimeLayout), i)
	}
	setupLogs(t, b.String())

	body := getLogsPage(t, "/logs")
	if n := strings.Count(body, `<li class="entry`); n != 1000 {
		t.Fatalf("showed %d entries, want 1000", n)
	}
	assertContains(t, body, "Entry 1004<", "Entry 5<", "Showing the newest 1,000 of 1,005 entries.", `<a href="/logs?all=1">Show all</a>`)
	if strings.Contains(body, "Entry 4<") {
		t.Error("showed an entry older than the newest 1,000")
	}

	all := getLogsPage(t, "/logs?all=1")
	if n := strings.Count(all, `<li class="entry`); n != 1005 {
		t.Fatalf("showed %d entries with all, want 1005", n)
	}
	if strings.Contains(all, "Showing the newest") {
		t.Error("says entries were left out when all of them are shown")
	}
}

func TestLogsPageWithAnEmptyOrMissingLog(t *testing.T) {
	path := setupLogs(t, "")
	assertContains(t, getLogsPage(t, "/logs"), "The log is empty.")

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	assertContains(t, getLogsPage(t, "/logs"), "Couldn't read the log.", "certkit-keystore.log")
}

func TestLogsPageReadsTheJournal(t *testing.T) {
	day := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	runs := setupJournal(t,
		journalLine(day.Add(-time.Second), "certkit-keystore", "2026/10/26 23:59:59 Poll failed: dial tcp: connection refused")+
			journalLine(day.Add(time.Second), "systemd", "Started CertKit Keystore.")+
			// journalctl prints a message that isn't UTF-8 as its bytes.
			fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%d","SYSLOG_IDENTIFIER":"certkit-keystore","MESSAGE":[104,105,255]}`+"\n", day.Add(2*time.Second).UnixMicro()),
		nil)

	body := getLogsPage(t, "/logs")
	assertInOrder(t, body, "Tuesday, Oct 27, 2026", "hi�", "systemd: Started CertKit Keystore.", "Monday, Oct 26, 2026", "Poll failed")
	assertContains(t, body,
		// The journal's date, without the log package's.
		`<li class="entry error"><time title="2026/10/26 23:59:59 UTC">23:59:59</time><span class="msg">Poll failed: dial tcp`,
		"journalctl -u certkit-keystore", `All<span class="n">3</span>`,
	)
	if len(*runs) != 1 || !slices.Contains((*runs)[0], "--unit=certkit-keystore.service") || !slices.Contains((*runs)[0], "--output=json") {
		t.Fatalf("ran journalctl %v, want the service's entries as JSON", *runs)
	}
}

func TestLogsPageWithoutJournalctl(t *testing.T) {
	setupJournal(t, "", &exec.Error{Name: "journalctl", Err: exec.ErrNotFound})

	assertContains(t, getLogsPage(t, "/logs"), "Couldn't read the log.", "journalctl isn&#39;t available here", "docker logs")
}

func TestLogsDownloadFromTheJournal(t *testing.T) {
	runs := setupJournal(t, "2026-10-27T00:00:01+0000 host certkit-keystore[42]: 2026/10/27 00:00:01 Keystore running.\n", nil)

	res := browse(handleLogsDownload, http.MethodGet, "/logs/download")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if cd := res.Header.Get("Content-Disposition"); cd != `attachment; filename="certkit-keystore.log"` {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}
	assertContains(t, responseBody(t, res), "Keystore running.")
	if len(*runs) != 1 || !slices.Contains((*runs)[0], "--output=short-iso") {
		t.Fatalf("ran journalctl %v, want the journal as text", *runs)
	}
}

func TestLogsDownload(t *testing.T) {
	setupLogs(t, sampleLog)

	res := browse(handleLogsDownload, http.MethodGet, "/logs/download")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if cd := res.Header.Get("Content-Disposition"); cd != `attachment; filename="certkit-keystore.log"` {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}
	if body := responseBody(t, res); body != sampleLog {
		t.Errorf("body = %q, want the log file", body)
	}
}

func TestReadLogTailStartsAtALine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certkit-keystore.log")
	if err := os.WriteFile(path, []byte("first line\nsecond line\nthird line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	data, size, err := readLogTail(path, 15)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "third line\n" || size != 34 {
		t.Fatalf("read %q of %d bytes, want the last whole line of 34 bytes", data, size)
	}

	if data, _, _ := readLogTail(path, 100); string(data) != "first line\nsecond line\nthird line\n" {
		t.Fatalf("read %q, want the whole file", data)
	}
}

func TestLogLevel(t *testing.T) {
	for message, want := range map[string]string{
		"Poll failed: dial tcp: connection refused":                            "error",
		"Startup check FAILED: Storage directory is not writable":              "error",
		"Failed to send status update to CertKit: EOF":                         "error",
		"http: TLS handshake error from 10.0.0.5:51234: EOF":                   "error",
		"Invalid encryption key: wrong length":                                 "error",
		"Warning: could not open firewall for port 8989":                       "warning",
		"Waiting for encryption key from CertKit: status=503 (retrying in 5s)": "warning",
		"Self-update: rejecting version 2.1.0: checksum mismatch":              "warning",
		"All startup checks passed":                                            "",
		"Agent 4kd8 requesting cert abc (config c1, collection col1)":          "",
		"Status page: alice@example.com logged in":                             "",
	} {
		if got := logLevel(message); got != want {
			t.Errorf("logLevel(%q) = %q, want %q", message, got, want)
		}
	}
}

func TestHighlight(t *testing.T) {
	got := highlight("Agent agent AGENT", "agent")
	want := []logPart{{"Agent", true}, {" ", false}, {"agent", true}, {" ", false}, {"AGENT", true}}
	if !slices.Equal(got, want) {
		t.Errorf("highlight = %v, want %v", got, want)
	}

	// Non-ASCII text before a match doesn't move it.
	got = highlight("Größe: Agent", "agent")
	want = []logPart{{"Größe: ", false}, {"Agent", true}}
	if !slices.Equal(got, want) {
		t.Errorf("highlight = %v, want %v", got, want)
	}
}
