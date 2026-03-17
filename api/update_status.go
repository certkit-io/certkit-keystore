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

type CertStatus string

var CertStatuses = struct {
	Synced        CertStatus
	KeyNotFound   CertStatus
	CertNotStored CertStatus
	PendingCSR    CertStatus
	GeneralError  CertStatus
}{
	Synced:        "Synced",
	KeyNotFound:   "KeyNotFound",
	CertNotStored: "CertNotStored",
	PendingCSR:    "PendingCSR",
	GeneralError:  "GeneralError",
}

type UpdateStatusRequest struct {
	Statuses []UpdateStatusItem `json:"statuses"`
}

type UpdateStatusItem struct {
	CustomCertId string     `json:"customCertId"`
	Status       CertStatus `json:"status"`
	Message      string     `json:"message,omitempty"`
}

func UpdateStatus(statuses []UpdateStatusItem) error {
	cfg := &config.CurrentConfig
	v := config.CurrentVersion

	priv, err := cfg.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}

	body, err := json.Marshal(UpdateStatusRequest{Statuses: statuses})
	if err != nil {
		return fmt.Errorf("marshal update-status request: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") +
		"/api/keystore/v1/" + cfg.Keystore.Id + "/update-status"

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
		return fmt.Errorf("update-status failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}
