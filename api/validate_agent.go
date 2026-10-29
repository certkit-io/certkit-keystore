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

type AgentRequest struct {
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type ValidateAgentRequestPayload struct {
	AgentSqid    string       `json:"agent_sqid"`
	AgentRequest AgentRequest `json:"agent_request"`
}

// ValidateAgentResponse is CertKit's answer to an agent's fetch request. When
// it is valid, CollectionId and CertificateId name the certificate the agent
// may fetch: CertKit has checked that the agent is configured for it and that
// its collection uses this keystore.
type ValidateAgentResponse struct {
	Valid         bool   `json:"valid"`
	CollectionId  string `json:"collection_id"`
	CertificateId string `json:"certificate_id"`
}

func ValidateAgentRequest(agentSqid string, agentReq AgentRequest) (*ValidateAgentResponse, error) {
	cfg := &config.CurrentConfig
	v := config.CurrentVersion

	priv, err := cfg.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}

	payload := ValidateAgentRequestPayload{
		AgentSqid:    agentSqid,
		AgentRequest: agentReq,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal validate request: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") +
		"/api/keystore/v2/" + cfg.Keystore.Id + "/validate-agent-request"

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
		return nil, fmt.Errorf("agent validation failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var result ValidateAgentResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode validate response: %w", err)
	}

	if !result.Valid {
		return nil, fmt.Errorf("agent request not valid")
	}
	if result.CollectionId == "" || result.CertificateId == "" {
		return nil, fmt.Errorf("validation did not name a certificate")
	}

	return &result, nil
}
