//go:build windows

package install

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	DefaultConfigPath         = `C:\ProgramData\CertKit\certkit-keystore\config.json`
	DefaultStorageDir         = `C:\ProgramData\CertKit\certkit-keystore\certificates`
	defaultServiceDescription = "CertKit Keystore service"
	windowsEventLogSource     = "CertKit"
	windowsEventLogAppRegPath = `SYSTEM\CurrentControlSet\Services\EventLog\Application`
)

func InstallService(configPath string) {
	mustBeAdmin()

	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("failed to determine executable path: %v", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		log.Fatalf("failed to resolve executable symlinks: %v", err)
	}

	if _, err := os.Stat(exe); err != nil {
		log.Fatalf("binary path does not exist: %s (%v)", exe, err)
	}
	if !filepath.IsAbs(exe) {
		log.Fatalf("executable path must be absolute: %s", exe)
	}
	if !filepath.IsAbs(configPath) {
		log.Fatalf("config path must be an absolute path: %s", configPath)
	}

	manager, err := mgr.Connect()
	if err != nil {
		log.Fatalf("failed to connect to service manager: %v", err)
	}
	defer manager.Disconnect()

	svcObj, err := manager.OpenService(ServiceName)
	if err != nil {
		svcObj, err = manager.CreateService(
			ServiceName,
			exe,
			mgr.Config{
				DisplayName:      ServiceName,
				StartType:        mgr.StartAutomatic,
				ServiceStartName: "LocalSystem",
				Description:      defaultServiceDescription,
			},
			"run",
			"--service",
			"--config",
			configPath,
		)
		if err != nil {
			log.Fatalf("failed to create service %s: %v", ServiceName, err)
		}
		defer svcObj.Close()
	} else {
		defer svcObj.Close()
		binLine := fmt.Sprintf(`"%s" run --service --config "%s"`, exe, configPath)
		current, err := svcObj.Config()
		if err != nil {
			log.Fatalf("failed to read service config %s: %v", ServiceName, err)
		}
		current.DisplayName = ServiceName
		current.StartType = mgr.StartAutomatic
		current.ServiceStartName = "LocalSystem"
		current.BinaryPathName = binLine
		current.Description = defaultServiceDescription
		if err := svcObj.UpdateConfig(current); err != nil {
			log.Fatalf("failed to update service %s: %v", ServiceName, err)
		}
	}

	if err := ensureWindowsEventLogSource(); err != nil {
		log.Printf("Warning: failed to register Windows Event Log source %q: %v", windowsEventLogSource, err)
	}

	if err := configureRecovery(svcObj); err != nil {
		log.Fatalf("failed to configure service recovery: %v", err)
	}

	status, err := svcObj.Query()
	if err != nil {
		log.Fatalf("failed to query service %s: %v", ServiceName, err)
	}
	if status.State != svc.Running {
		if err := svcObj.Start(); err != nil {
			log.Fatalf("failed to start service %s: %v", ServiceName, err)
		}
	}

	log.Printf("Installed and started service %s", ServiceName)
	log.Printf("   Get-Service %s", ServiceName)
}

func configureRecovery(s *mgr.Service) error {
	return s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
	}, 86400)
}

func mustBeAdmin() {
	ok, err := isElevatedAdmin()
	if err != nil {
		log.Fatalf("failed to check administrator elevation: %v", err)
	}
	if !ok {
		log.Fatal("this command must be run from an elevated Administrator prompt")
	}
}

func isElevatedAdmin() (bool, error) {
	token := windows.Token(0)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false, err
	}
	defer token.Close()

	if !token.IsElevated() {
		return false, nil
	}

	return true, nil
}

func stopWindowsService(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	if status.State == svc.Stopped {
		return nil
	}

	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stop: %w", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("query after stop: %w", err)
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("service %s did not stop in time", ServiceName)
}

func ensureWindowsEventLogSource() error {
	appkey, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsEventLogAppRegPath, registry.CREATE_SUB_KEY)
	if err != nil {
		return err
	}
	defer appkey.Close()

	sk, _, err := registry.CreateKey(appkey, windowsEventLogSource, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer sk.Close()

	messageFile := selectWindowsEventMessageFile()
	if err := sk.SetDWordValue("CustomSource", 1); err != nil {
		return err
	}
	if err := sk.SetExpandStringValue("EventMessageFile", messageFile); err != nil {
		return err
	}
	if err := sk.SetDWordValue("TypesSupported", eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		return err
	}

	if el, err := eventlog.Open(windowsEventLogSource); err == nil {
		_ = el.Close()
	}

	return nil
}

func removeWindowsEventLogSource() error {
	err := eventlog.Remove(windowsEventLogSource)
	if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return err
	}
	return nil
}

func selectWindowsEventMessageFile() string {
	candidates := []string{
		`%SystemRoot%\System32\EventCreate.exe`,
		`%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll`,
		`%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\EventLogMessages.dll`,
	}

	for _, candidate := range candidates {
		expanded := os.ExpandEnv(candidate)
		if _, err := os.Stat(expanded); err == nil {
			return candidate
		}
	}

	return candidates[len(candidates)-1]
}
