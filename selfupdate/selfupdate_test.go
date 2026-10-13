package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignalUpdateAvailable(t *testing.T) {
	t.Cleanup(func() { pendingUpdate = nil })

	tests := []struct {
		name                          string
		current, version, url, sha256 string
		wantQueued                    bool
	}{
		{"new version", "v1.0.0", "v1.1.0", "https://example/bin", "abc", true},
		{"same version", "v1.1.0", "v1.1.0", "https://example/bin", "abc", false},
		{"missing url", "v1.0.0", "v1.1.0", "", "abc", false},
		{"missing checksum", "v1.0.0", "v1.1.0", "https://example/bin", "", false},
		{"blank version", "v1.0.0", "  ", "https://example/bin", "abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pendingUpdate = nil
			SignalUpdateAvailable(tt.current, tt.version, tt.url, tt.sha256)
			if got := pendingUpdate != nil; got != tt.wantQueued {
				t.Fatalf("queued = %v, want %v", got, tt.wantQueued)
			}
		})
	}
}

func TestDownloadAndVerify(t *testing.T) {
	payload := []byte("new keystore binary")
	sum := sha256.Sum256(payload)
	goodSHA := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bin" {
			http.NotFound(w, r)
			return
		}
		w.Write(payload)
	}))
	defer srv.Close()

	tests := []struct {
		name    string
		path    string
		sha     string
		wantErr string
	}{
		{"checksum matches", "/bin", goodSHA, ""},
		{"checksum matches case-insensitively", "/bin", strings.ToUpper(goodSHA), ""},
		{"checksum mismatch", "/bin", strings.Repeat("0", 64), "checksum mismatch"},
		{"http error", "/missing", goodSHA, "HTTP 404"},
		{"empty checksum", "/bin", "", "checksum is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			dest := filepath.Join(dir, "certkit-keystore.new")

			err := downloadAndVerify(srv.URL+tt.path, tt.sha, dest)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				got, readErr := os.ReadFile(dest)
				if readErr != nil {
					t.Fatalf("read destination: %v", readErr)
				}
				if string(got) != string(payload) {
					t.Fatalf("destination content = %q, want %q", got, payload)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			// A rejected download must leave nothing behind: no destination, no temp file.
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatalf("expected empty dir after failed download, found %d entries", len(entries))
			}
		})
	}
}
