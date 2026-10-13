//go:build windows

package main

import (
	"path/filepath"
	"testing"

	"github.com/certkit-io/certkit-keystore/config"
)

func TestEnsureMsiConfig(t *testing.T) {
	type args struct{ key, host, port, storageDir string }
	fresh := args{"app.ks1", "localhost", "8443", `C:\certkit\certs\.`}

	tests := []struct {
		name     string
		existing *config.Config // written before the call; nil = no config
		args     args
		wantErr  bool
		wantHost string // expected host in the resulting config
		wantDir  string // expected storage dir when the config is (re)created
	}{
		{name: "fresh install", args: fresh, wantHost: "localhost", wantDir: `C:\certkit\certs`},
		{name: "trailing backslash from MSI", args: args{"app.ks1", "localhost", "443", `C:\certkit\certs\\.`}, wantHost: "localhost", wantDir: `C:\certkit\certs`},
		{name: "missing key", args: args{"", "localhost", "443", `C:\certs`}, wantErr: true},
		{name: "missing host", args: args{"app.ks1", "", "443", `C:\certs`}, wantErr: true},
		{name: "malformed key", args: args{"nodot", "localhost", "443", `C:\certs`}, wantErr: true},
		{name: "invalid port", args: args{"app.ks1", "localhost", "70000", `C:\certs`}, wantErr: true},
		{name: "relative storage dir", args: args{"app.ks1", "localhost", "443", `certs`}, wantErr: true},
		{
			name:     "initialized config kept even with a new key",
			existing: &config.Config{Keystore: &config.KeystoreInfo{Id: "old", ApplicationId: "app", Host: "old-host", Port: "443", Initialized: true}},
			args:     fresh,
			wantHost: "old-host",
		},
		{
			name:     "uninitialized config kept without a key (upgrade)",
			existing: &config.Config{Keystore: &config.KeystoreInfo{Id: "old", ApplicationId: "app", Host: "old-host", Port: "443"}},
			args:     args{"", "", "443", `C:\certs\.`},
			wantHost: "old-host",
		},
		{
			name:     "uninitialized config replaced by a new key",
			existing: &config.Config{Keystore: &config.KeystoreInfo{Id: "old", ApplicationId: "app", Host: "old-host", Port: "443"}},
			args:     fresh,
			wantHost: "localhost",
			wantDir:  `C:\certkit\certs`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.json")
			if tt.existing != nil {
				if err := config.SaveConfig(tt.existing, configPath); err != nil {
					t.Fatal(err)
				}
			}

			err := ensureMsiConfig(configPath, tt.args.key, tt.args.host, tt.args.port, tt.args.storageDir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got, err := config.ReadConfig(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if got.Keystore.Host != tt.wantHost {
				t.Errorf("host = %q, want %q", got.Keystore.Host, tt.wantHost)
			}
			if tt.wantDir != "" && got.Keystore.StorageDir != tt.wantDir {
				t.Errorf("storage dir = %q, want %q", got.Keystore.StorageDir, tt.wantDir)
			}
		})
	}
}
