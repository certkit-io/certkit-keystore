package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/certkit-io/certkit-keystore/utils"
)

func ComputeBodySHA256Base64url(req *http.Request) (string, error) {
	if req.Body == nil {
		sum := sha256.Sum256(nil)
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	}

	b, err := io.ReadAll(req.Body)
	if err != nil {
		return "", fmt.Errorf("read request body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(b))

	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func canonicalPathAndQuery(u *url.URL) string {
	if u == nil {
		return "/"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		return path + "?" + u.RawQuery
	}
	return path
}

func canonicalHost(req *http.Request) string {
	h := strings.TrimSpace(req.Host)
	if h != "" {
		return strings.ToLower(h)
	}
	if req.URL != nil {
		return strings.ToLower(req.URL.Host)
	}
	return ""
}

func buildSigningString(method, pathQuery, host string, ts int64, bodyHash string) string {
	return strings.Join([]string{
		"method: " + strings.ToUpper(method),
		"path: " + pathQuery,
		"host: " + strings.ToLower(host),
		"ts: " + strconv.FormatInt(ts, 10),
		"body_sha256: " + bodyHash,
	}, "\n")
}

// SignRequest signs the request with ed25519 and sets auth headers.
func SignRequest(req *http.Request, keystoreID string, keystoreVersion string, priv ed25519.PrivateKey, now time.Time) error {
	if req == nil {
		return fmt.Errorf("req is nil")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid ed25519 private key length: got %d", len(priv))
	}
	if keystoreID == "" {
		return fmt.Errorf("keystoreID is required")
	}
	if req.URL == nil {
		return fmt.Errorf("req.URL is nil")
	}

	ts := now.UTC().Unix()

	bodyHash, err := ComputeBodySHA256Base64url(req)
	if err != nil {
		return err
	}

	pathQuery := canonicalPathAndQuery(req.URL)
	host := canonicalHost(req)
	if host == "" {
		return fmt.Errorf("missing host (req.Host and req.URL.Host both empty)")
	}

	signingString := buildSigningString(req.Method, pathQuery, host, ts, bodyHash)
	sig := ed25519.Sign(priv, []byte(signingString))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	machineId, err := utils.GetStableMachineID()
	if err != nil {
		return fmt.Errorf("get machine id: %w", err)
	}

	req.Header.Set("X-Keystore-Id", keystoreID)
	req.Header.Set("X-Machine-Id", machineId)
	if keystoreVersion != "" {
		req.Header.Set("X-Keystore-Version", keystoreVersion)
	}
	req.Header.Set("X-Keystore-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Keystore-Content-SHA256", bodyHash)

	req.Header.Set("Authorization",
		fmt.Sprintf(
			`KeystoreSig keystoreId="%s", alg="ed25519", sig="%s", signed="method path host ts body_sha256"`,
			keystoreID, sigB64,
		),
	)

	return nil
}
