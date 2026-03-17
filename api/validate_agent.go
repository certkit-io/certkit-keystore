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

type ValidateAgentResponse struct {
	Valid bool `json:"valid"`
}

func ValidateAgentRequest(agentSqid string, agentReq AgentRequest) error {
	cfg := &config.CurrentConfig
	v := config.CurrentVersion

	priv, err := cfg.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}

	payload := ValidateAgentRequestPayload{
		AgentSqid:    agentSqid,
		AgentRequest: agentReq,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal validate request: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") +
		"/api/keystore/v1/" + cfg.Keystore.Id + "/validate-agent-request"

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
		return fmt.Errorf("agent validation failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var result ValidateAgentResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("decode validate response: %w", err)
	}

	if !result.Valid {
		return fmt.Errorf("agent request not valid")
	}

	return nil
}
