package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/certkit-io/certkit-keystore/config"
	"github.com/certkit-io/certkit-keystore/utils"
)

type RegisterKeystoreRequest struct {
	RegistrationKey string `json:"registration_key"`
	PublicKey        string `json:"public_key"`
	KeystoreBaseUrl  string `json:"keystore_base_url"`
	MachineId        string `json:"machine_id"`
	Hostname         string `json:"hostname"`
	Version          string `json:"version"`
	OperatingSystem  string `json:"operating_system"`
	Timezone         string `json:"timezone"`
	PathToBin        string `json:"path_to_bin"`
	PathToConfig     string `json:"path_to_config"`
	HostType         string `json:"host_type"`
	StorageDir       string `json:"storageDir"`
	ServiceName      string `json:"service_name"`
}

type RegisterKeystoreResponse struct {
	Success    bool   `json:"success"`
	KeystoreId string `json:"keystore_id"`
}

func RegisterKeystore() (*RegisterKeystoreResponse, error) {
	v := config.CurrentVersion
	cfg := &config.CurrentConfig

	hostname, _ := os.Hostname()

	binPath, _ := os.Executable()
	if binPath != "" {
		binPath, _ = filepath.EvalSymlinks(binPath)
	}

	machineId, _ := utils.GetStableMachineID()

	req := RegisterKeystoreRequest{
		RegistrationKey: cfg.Keystore.ApplicationId + "." + cfg.Keystore.Id,
		PublicKey:        cfg.Auth.KeyPair.PublicKey,
		KeystoreBaseUrl:  cfg.Keystore.BaseUrl(),
		MachineId:        machineId,
		Hostname:         hostname,
		Version:          v.Version,
		OperatingSystem:  runtime.GOOS,
		Timezone:         utils.FormatTimezone(),
		PathToBin:        binPath,
		PathToConfig:     config.CurrentPath,
		HostType:         utils.DetectHostType(),
		StorageDir:       cfg.Keystore.StorageDir,
		ServiceName:      cfg.Keystore.ServiceName,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal json: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") + "/api/keystore/v1/register-keystore"

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
