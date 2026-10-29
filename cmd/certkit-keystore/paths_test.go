package main

import (
	"path/filepath"
	"testing"

	keystoreInstall "github.com/certkit-io/certkit-keystore/install"
)

func TestConfigPathMovesOnlyInDevBuilds(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(devDirEnv, dir)
	prev := version
	t.Cleanup(func() { version = prev })

	version = "2.0.0"
	if got := configPath(); got != keystoreInstall.ConfigPath {
		t.Errorf("release build: configPath() = %q, want %q", got, keystoreInstall.ConfigPath)
	}

	version = "dev"
	if got, want := configPath(), filepath.Join(dir, "config.json"); got != want {
		t.Errorf("dev build: configPath() = %q, want %q", got, want)
	}
}
