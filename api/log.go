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

type EventType string

var LogEvents = struct {
	Startup EventType
	Info    EventType
}{
	Startup: "startup",
	Info:    "info",
}

type LogKeystoreEventRequest struct {
	Message   string    `json:"message"`
	EventType EventType `json:"eventType"`
	IsError   bool      `json:"isError"`
}

func LogKeystoreEvent(message string, eventType EventType, isError bool) error {
	cfg := &config.CurrentConfig
	v := config.CurrentVersion

	priv, err := cfg.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}

	body, err := json.Marshal(LogKeystoreEventRequest{
		Message:   message,
		EventType: eventType,
		IsError:   isError,
	})
	if err != nil {
		return fmt.Errorf("marshal log request: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") +
		"/api/keystore/v1/" + cfg.Keystore.Id + "/log"

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
		return fmt.Errorf("log failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}
