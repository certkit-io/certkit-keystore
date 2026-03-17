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

type UpdateKeystoreInfoRequest struct {
	CACertificate string `json:"caCertificate"`
}

func UpdateCAInfo(caCertPEM string) error {
	cfg := &config.CurrentConfig
	v := config.CurrentVersion

	priv, err := cfg.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}

	body, err := json.Marshal(UpdateKeystoreInfoRequest{
		CACertificate: caCertPEM,
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") +
		"/api/keystore/v1/" + cfg.Keystore.Id + "/update-ca-info"

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if err := auth.SignRequest(httpReq, cfg.Keystore.Id, v.Version, priv, time.Now()); err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update-info failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}
