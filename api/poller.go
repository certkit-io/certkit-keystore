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

type PollRequest struct{}

type PollResponse struct {
	Certificates []PollCertificate `json:"certificates"`
}

type PollCertificate struct {
	CustomCertId     string      `json:"customCertId"`
	LatestIssuedCert *IssuedCert `json:"latestIssuedCert"`
	CSR              *CSRInfo    `json:"csr"`
}

type IssuedCert struct {
	Id           int       `json:"id"`
	SHA1         string    `json:"sha1"`
	SHA256       string    `json:"sha256"`
	SerialNumber string    `json:"serialNumber"`
	PEM          string    `json:"pem"`
	Chain        string    `json:"chain"`
	Key          string    `json:"key"`
	IssueDate    time.Time `json:"issueDate"`
}

type KeyAlgorithm string

const (
	KeyAlgorithmEC256   KeyAlgorithm = "EC256"
	KeyAlgorithmRSA2048 KeyAlgorithm = "RSA2048"
)

type CSRInfo struct {
	SANs         []string     `json:"sans"`
	KeyAlgorithm KeyAlgorithm `json:"keyAlgorithm"`
}

func PollForConfiguration(v config.VersionInfo) (*PollResponse, error) {
	cfg := &config.CurrentConfig

	priv, err := cfg.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}

	body, err := json.Marshal(PollRequest{})
	if err != nil {
		return nil, fmt.Errorf("marshal poll request: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") +
		"/api/keystore/v1/" + cfg.Keystore.Id + "/poll"

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

	switch resp.StatusCode {
	case http.StatusNoContent:
		return &PollResponse{}, nil
	case http.StatusOK:
		var result PollResponse
		if err := json.Unmarshal(respBody, &result); err != nil {
			return nil, fmt.Errorf("decode poll response: %w", err)
		}
		return &result, nil
	case http.StatusForbidden:
		return nil, fmt.Errorf("keystore unauthorized (403)")
	default:
		return nil, fmt.Errorf("poll failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}
}
