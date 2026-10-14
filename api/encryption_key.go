package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/certkit-io/certkit-keystore/auth"
	"github.com/certkit-io/certkit-keystore/config"
	keystoreCrypto "github.com/certkit-io/certkit-keystore/crypto"
)

type EncryptionKeyRequest struct{}

type EncryptionKeyResponse struct {
	Key string `json:"key"`
}

// FetchEncryptionKey gets this keystore's at-rest encryption key from
// CertKit, which creates it on the first request and never changes it. The
// key must only ever be held in memory.
func FetchEncryptionKey() ([]byte, error) {
	cfg := &config.CurrentConfig
	v := config.CurrentVersion

	priv, err := cfg.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}

	body, err := json.Marshal(EncryptionKeyRequest{})
	if err != nil {
		return nil, fmt.Errorf("marshal encryption-key request: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") +
		"/api/keystore/v1/" + cfg.Keystore.Id + "/encryption-key"

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if err := auth.SignRequest(httpReq, cfg.Keystore.Id, v.Version, priv, time.Now()); err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("encryption-key failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var result EncryptionKeyResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode encryption-key response: %w", err)
	}

	key, err := base64.StdEncoding.DecodeString(result.Key)
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}
	if len(key) != keystoreCrypto.EncryptionKeySize {
		return nil, fmt.Errorf("invalid encryption key length: got %d, want %d", len(key), keystoreCrypto.EncryptionKeySize)
	}

	return key, nil
}
