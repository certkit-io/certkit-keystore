package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/certkit-io/certkit-keystore/config"
)

type RegisterKeystoreRequest struct {
	RegistrationKey string   `json:"registration_key"`
	PublicKey       string   `json:"public_key"`
	HostInfo        HostInfo `json:"host_info"`
}

type RegisterKeystoreResponse struct {
	Success    bool   `json:"success"`
	KeystoreId string `json:"keystore_id"`
}

func RegisterKeystore() (*RegisterKeystoreResponse, error) {
	cfg := &config.CurrentConfig

	req := RegisterKeystoreRequest{
		RegistrationKey: cfg.Keystore.RegistrationKey(),
		PublicKey:       cfg.Auth.KeyPair.PublicKey,
		HostInfo:        CollectHostInfo(),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal json: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") + "/api/keystore/v2/register-keystore"

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

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
		return nil, fmt.Errorf("registration failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var result RegisterKeystoreResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode register response: %w", err)
	}

	return &result, nil
}
