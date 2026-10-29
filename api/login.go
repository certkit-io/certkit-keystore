package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/certkit-io/certkit-keystore/auth"
	"github.com/certkit-io/certkit-keystore/config"
)

type RedeemLoginRequest struct {
	Code     string `json:"code"`
	Verifier string `json:"verifier"`
}

// RedeemLoginResponse names the CertKit user who signed in to the status page.
type RedeemLoginResponse struct {
	Email string `json:"email"`
}

// RedeemLogin asks CertKit who a status page sign-in code belongs to. CertKit
// only answers for a fresh code it issued to this keystore, together with the
// verifier whose hash the sign-in started with.
func RedeemLogin(code string, verifier string) (*RedeemLoginResponse, error) {
	cfg := &config.CurrentConfig
	v := config.CurrentVersion

	priv, err := cfg.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}

	body, err := json.Marshal(RedeemLoginRequest{Code: code, Verifier: verifier})
	if err != nil {
		return nil, fmt.Errorf("marshal redeem-login request: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") +
		"/api/keystore/v2/" + cfg.Keystore.Id + "/redeem-login"

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
		return nil, fmt.Errorf("redeem-login failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var result RedeemLoginResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode redeem-login response: %w", err)
	}
	if result.Email == "" {
		return nil, fmt.Errorf("redeem-login did not name a user")
	}

	return &result, nil
}
