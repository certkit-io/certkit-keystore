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

	"github.com/certkit-io/certkit-keystore/auth"
	"github.com/certkit-io/certkit-keystore/config"
	"github.com/certkit-io/certkit-keystore/utils"
)

// HostInfo describes the keystore and the machine it runs on. It is sent when
// the keystore registers and again at every start, so CertKit always shows
// current details.
type HostInfo struct {
	Version         string   `json:"version"`
	Hostname        string   `json:"hostname"`
	MachineId       string   `json:"machine_id"`
	OperatingSystem string   `json:"operating_system"`
	OsVersion       string   `json:"os_version"`
	Architecture    string   `json:"architecture"`
	Timezone        string   `json:"timezone"`
	HostType        string   `json:"host_type"`
	InstallType     string   `json:"install_type"`
	RunAsUser       string   `json:"run_as_user"`
	IpAddresses     []string `json:"ip_addresses"`
	KeystoreBaseUrl string   `json:"keystore_base_url"`
	PathToBin       string   `json:"path_to_bin"`
	PathToConfig    string   `json:"path_to_config"`
	StorageDir      string   `json:"storage_dir"`
	ServiceName     string   `json:"service_name"`
}

func CollectHostInfo() HostInfo {
	cfg := &config.CurrentConfig

	hostname, _ := os.Hostname()

	binPath, _ := os.Executable()
	if binPath != "" {
		binPath, _ = filepath.EvalSymlinks(binPath)
	}

	machineId, _ := utils.GetStableMachineID()

	return HostInfo{
		Version:         config.CurrentVersion.Version,
		Hostname:        hostname,
		MachineId:       machineId,
		OperatingSystem: runtime.GOOS,
		OsVersion:       utils.OSVersion(),
		Architecture:    runtime.GOARCH,
		Timezone:        utils.FormatTimezone(),
		HostType:        utils.DetectHostType(),
		InstallType:     utils.DetectInstallType(),
		RunAsUser:       utils.RunAsUser(),
		IpAddresses:     utils.LocalIPAddresses(),
		KeystoreBaseUrl: cfg.Keystore.BaseUrl(),
		PathToBin:       binPath,
		PathToConfig:    absPath(config.CurrentPath),
		StorageDir:      absPath(cfg.Keystore.StorageDir),
		ServiceName:     cfg.Keystore.ServiceName,
	}
}

func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

type HostInfoRequest struct {
	HostInfo      HostInfo `json:"host_info"`
	CACertificate string   `json:"ca_certificate"`
}

// SendHostInfo sends CertKit this keystore's host details and its CA
// certificate, which agents use to trust the keystore. Both can change
// between runs, so this is called at every start.
func SendHostInfo(caCertPEM string) error {
	cfg := &config.CurrentConfig
	v := config.CurrentVersion

	priv, err := cfg.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}

	body, err := json.Marshal(HostInfoRequest{
		HostInfo:      CollectHostInfo(),
		CACertificate: caCertPEM,
	})
	if err != nil {
		return fmt.Errorf("marshal host-info request: %w", err)
	}

	url := strings.TrimRight(cfg.CertkitBaseUrl, "/") +
		"/api/keystore/v2/" + cfg.Keystore.Id + "/host-info"

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
		return fmt.Errorf("host-info failed: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}
