package server

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreInstall "github.com/certkit-io/certkit-keystore/install"
)

// The logs page shows the keystore's log as it is when the page loads,
// newest entries first, in the keystore's local time like the status page.
// On Linux the log is the service's journal; on Windows it's the log file the
// keystore writes. The log package has no levels, so errors and warnings are
// picked out by their words.

const (
	// logReadLimit is how much of the end of the log file the logs page
	// reads. The keystore cuts the file back to its last 10,000 lines once it
	// passes 5 MB, so that's normally all of it.
	logReadLimit = 8 << 20
	// journalEntries is how many of the newest journal entries the logs page
	// reads, and downloadJournalEntries how many a download has.
	journalEntries         = 10000
	downloadJournalEntries = 100000
	// logPageEntries is how many entries the logs page shows unless asked
	// for all of them.
	logPageEntries = 1000
	// logTimeLayout is the date the log package starts each line with.
	logTimeLayout = "2006/01/02 15:04:05"
)

var (
	errorWords   = regexp.MustCompile(`(?i)\b(fail(s|ed|ure)?|errors?|invalid|panic|fatal)\b`)
	warningWords = regexp.MustCompile(`(?i)\b(warning|retrying|rejecting)\b`)
)

// useJournal is set where the keystore logs to journald instead of a file.
var useJournal = runtime.GOOS == "linux"

// journalctl runs journalctl and returns what it printed; tests replace it.
var journalctl = func(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "journalctl", args...).Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		err = fmt.Errorf("%w: %s", err, bytes.TrimSpace(exitErr.Stderr))
	}
	return out, err
}

//go:embed logs_page.html
var logsPageHTML string

var logsPageTemplate = template.Must(template.New("logs").Parse(logsPageHTML))

type logEntry struct {
	// Time is zero for lines read before the first dated one.
	Time    time.Time
	Message string
	// Level is "error", "warning" or "".
	Level string
}

type logsPage struct {
	CertkitURL    string
	ManagementURL string
	Version       config.VersionInfo
	// Source says where the log is.
	Source string
	Size   string
	Zone   string
	// Err is why the log couldn't be read.
	Err string

	Query    string
	Problems bool
	// AllCount and ProblemCount count the entries that match the search.
	AllCount     string
	ProblemCount string
	Days         []logDay
	// Empty is shown instead of entries when there are none to show.
	Empty string
	// Summary says the page left older entries out, and ShowAllURL shows
	// them.
	Summary    string
	ShowAllURL string
	// Partial says the page didn't read all of the log.
	Partial string

	AllURL      string
	ProblemsURL string
	ClearURL    string
	Generated   string
}

// logDay is one day's entries, newest first.
type logDay struct {
	Date  string
	Lines []logLine
}

type logLine struct {
	Time  string
	Exact string
	Level string
	// Parts are the message, split around matches of the search.
	Parts []logPart
}

type logPart struct {
	Text  string
	Match bool
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	q := strings.TrimSpace(strings.ToValidUTF8(query.Get("q"), ""))
	page := buildLogsPage(q, query.Has("problems"), query.Has("all"), time.Now())

	var buf bytes.Buffer
	if err := logsPageTemplate.Execute(&buf, page); err != nil {
		log.Printf("Failed to render logs page: %v", err)
		http.Error(w, "failed to render logs page", http.StatusInternalServerError)
		return
	}
	writeHTML(w, http.StatusOK, buf.Bytes(), "'self'")
}

// handleLogsDownload sends the whole log file, or the service's journal.
func handleLogsDownload(w http.ResponseWriter, r *http.Request) {
	if useJournal {
		out, err := journalctl(journalArgs("short-iso", downloadJournalEntries)...)
		if err != nil {
			http.Error(w, "Couldn't read the log: "+journalError(err).Error(), http.StatusInternalServerError)
			return
		}
		setDownloadHeaders(w)
		w.Write(out)
		return
	}

	f, err := os.Open(config.CurrentLogPath)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		http.Error(w, "Couldn't read the log file: "+err.Error(), status)
		return
	}
	defer f.Close()
	setDownloadHeaders(w)
	http.ServeContent(w, r, "", time.Time{}, f)
}

func setDownloadHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="certkit-keystore.log"`)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

// logSnapshot is the log as the page read it.
type logSnapshot struct {
	Entries []logEntry
	Source  string
	Size    string
	Partial string
}

func readLog() (logSnapshot, error) {
	if useJournal {
		return readJournal()
	}
	return readLogFile(config.CurrentLogPath)
}

func readLogFile(path string) (logSnapshot, error) {
	snap := logSnapshot{Source: absPath(path)}
	data, size, err := readLogTail(path, logReadLimit)
	if err != nil {
		return snap, err
	}
	snap.Entries, snap.Size = parseLog(data), formatSize(size)
	if size > logReadLimit {
		snap.Partial = "The log file is " + formatSize(size) + ", and this page shows its last " +
			formatSize(logReadLimit) + ". Download the log for the rest."
	}
	return snap, nil
}

func readJournal() (logSnapshot, error) {
	snap := logSnapshot{Source: "journalctl -u " + keystoreInstall.ServiceName}
	out, err := journalctl(journalArgs("json", journalEntries)...)
	if err != nil {
		return snap, journalError(err)
	}
	snap.Entries = parseJournal(out)
	if len(snap.Entries) >= journalEntries {
		snap.Partial = "This page shows the newest " + formatCount(journalEntries) +
			" journal entries. Download the log for older ones."
	}
	return snap, nil
}

// journalArgs has journalctl print the service's newest entries, in full.
func journalArgs(output string, entries int) []string {
	return []string{
		"--unit=" + keystoreInstall.ServiceName + ".service",
		"--output=" + output,
		"--lines=" + strconv.Itoa(entries),
		"--all", "--no-pager", "--quiet",
	}
}

// journalError explains a missing journalctl: containers have no journal.
func journalError(err error) error {
	if errors.Is(err, exec.ErrNotFound) {
		return errors.New("journalctl isn't available here. In a container, the keystore's log is the container's output (docker logs).")
	}
	return err
}

func buildLogsPage(q string, problems, all bool, now time.Time) logsPage {
	page := logsPage{
		CertkitURL:    certkitBaseURL(),
		ManagementURL: managementURL(),
		Version:       config.CurrentVersion,
		Zone:          now.Format("MST"),
		Query:         q,
		Problems:      problems,
		AllURL:        logsURL(q, false, false),
		ProblemsURL:   logsURL(q, true, false),
		ClearURL:      logsURL("", problems, false),
		Generated:     formatTime(now),
	}

	snap, err := readLog()
	page.Source, page.Size, page.Partial = snap.Source, snap.Size, snap.Partial
	if err != nil {
		page.Err = err.Error()
		return page
	}

	entries := snap.Entries
	var found, foundProblems []logEntry
	lq := asciiLower(q)
	for _, e := range entries {
		if q != "" && !strings.Contains(asciiLower(e.Message), lq) {
			continue
		}
		found = append(found, e)
		if e.Level != "" {
			foundProblems = append(foundProblems, e)
		}
	}
	page.AllCount, page.ProblemCount = formatCount(len(found)), formatCount(len(foundProblems))

	shown, kind := found, "entries"
	if problems {
		shown, kind = foundProblems, "problems"
	}
	if len(shown) == 0 {
		switch {
		case len(entries) == 0:
			page.Empty = "The log is empty."
		case q != "":
			page.Empty = "No " + kind + " match “" + q + "”."
		default:
			page.Empty = "No problems in the log."
		}
	}
	if n := len(shown); !all && n > logPageEntries {
		page.Summary = "Showing the newest " + formatCount(logPageEntries) + " of " + formatCount(n) + " " + kind + "."
		page.ShowAllURL = logsURL(q, problems, true)
		shown = shown[n-logPageEntries:]
	}
	page.Days = logDays(shown, q)
	return page
}

// readLogTail reads the end of the log file from the start of a line, at
// most limit bytes of it. It also returns the file's size.
func readLogTail(path string, limit int64) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}

	size := info.Size()
	start := max(size-limit, 0)
	data := make([]byte, size-start)
	n, err := f.ReadAt(data, start)
	// The log can be cut back while it's read.
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, size, err
	}
	data = data[:n]
	if start > 0 {
		// Skip what's left of the line the read started in.
		i := bytes.IndexByte(data, '\n')
		data = data[i+1:]
	}
	return data, size, nil
}

// parseLog splits a log into entries. A line that doesn't start with a date
// continues the entry before it.
func parseLog(data []byte) []logEntry {
	var entries []logEntry
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if t, message, ok := splitLogLine(line); ok {
			entries = append(entries, logEntry{Time: t, Message: message})
		} else if len(entries) > 0 {
			entries[len(entries)-1].Message += "\n" + line
		} else if line != "" {
			entries = append(entries, logEntry{Message: line})
		}
	}
	for i := range entries {
		entries[i].Message = strings.TrimRight(entries[i].Message, "\n")
		entries[i].Level = logLevel(entries[i].Message)
	}
	return entries
}

func splitLogLine(line string) (time.Time, string, bool) {
	n := len(logTimeLayout)
	if len(line) <= n || line[n] != ' ' {
		return time.Time{}, "", false
	}
	t, err := time.Parse(logTimeLayout, line[:n])
	if err != nil {
		return time.Time{}, "", false
	}
	return t, line[n+1:], true
}

// journalEntry is what the page uses of an entry in journalctl's JSON output.
type journalEntry struct {
	// Time is in microseconds since the Unix epoch.
	Time       string          `json:"__REALTIME_TIMESTAMP"`
	Identifier string          `json:"SYSLOG_IDENTIFIER"`
	Message    json.RawMessage `json:"MESSAGE"`
}

// parseJournal reads journalctl's JSON output, an entry per line. The journal
// keeps each line the keystore prints as an entry of its own, and has
// systemd's lines about the service too.
func parseJournal(data []byte) []logEntry {
	var entries []logEntry
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		var je journalEntry
		if err := json.Unmarshal(line, &je); err != nil {
			continue
		}
		usec, err := strconv.ParseInt(je.Time, 10, 64)
		if err != nil {
			continue
		}
		message := journalMessage(je.Message)
		// The journal dates entries itself.
		if _, m, ok := splitLogLine(message); ok {
			message = m
		}
		if je.Identifier == "systemd" {
			message = "systemd: " + message
		}
		entries = append(entries, logEntry{Time: time.UnixMicro(usec).UTC(), Message: message, Level: logLevel(message)})
	}
	return entries
}

// journalMessage decodes a MESSAGE field, which journalctl writes as an array
// of bytes when it isn't valid UTF-8.
func journalMessage(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b []byte
	if json.Unmarshal(raw, &b) == nil {
		return strings.ToValidUTF8(string(b), "�")
	}
	return ""
}

func logLevel(message string) string {
	switch {
	case errorWords.MatchString(message):
		return "error"
	case warningWords.MatchString(message):
		return "warning"
	}
	return ""
}

// logDays groups entries by the local day, newest first.
func logDays(entries []logEntry, q string) []logDay {
	var days []logDay
	for _, e := range slices.Backward(entries) {
		line := logLine{Level: e.Level, Parts: highlight(e.Message, q)}
		date := ""
		if !e.Time.IsZero() {
			local := e.Time.Local()
			line.Time, line.Exact = local.Format("15:04:05"), e.Time.Format(logTimeLayout)+" UTC"
			date = local.Format("Monday, Jan 2, 2006")
		}
		if len(days) == 0 || days[len(days)-1].Date != date {
			days = append(days, logDay{Date: date})
		}
		days[len(days)-1].Lines = append(days[len(days)-1].Lines, line)
	}
	return days
}

// highlight splits message around the places it matches q, ignoring case.
func highlight(message, q string) []logPart {
	if q == "" {
		return []logPart{{Text: message}}
	}
	var parts []logPart
	lower, lq := asciiLower(message), asciiLower(q)
	for {
		i := strings.Index(lower, lq)
		if i < 0 {
			break
		}
		if i > 0 {
			parts = append(parts, logPart{Text: message[:i]})
		}
		parts = append(parts, logPart{Text: message[i : i+len(q)], Match: true})
		message, lower = message[i+len(q):], lower[i+len(q):]
	}
	if message != "" {
		parts = append(parts, logPart{Text: message})
	}
	return parts
}

// asciiLower lowercases only ASCII letters, so the result lines up byte for
// byte with s.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// logsURL links to the logs page, searching for q, on the problems tab or
// not, and showing all entries or only the newest.
func logsURL(q string, problems, all bool) string {
	v := url.Values{}
	if q != "" {
		v.Set("q", q)
	}
	if problems {
		v.Set("problems", "1")
	}
	if all {
		v.Set("all", "1")
	}
	if len(v) == 0 {
		return "/logs"
	}
	return "/logs?" + v.Encode()
}

// formatCount writes n with thousands separators: 12,345.
func formatCount(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func formatSize(n int64) string {
	switch {
	case n < 1<<10:
		return plural(int(n), "byte")
	case n < 1<<20:
		return fmt.Sprintf("%d KB", n>>10)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
}
