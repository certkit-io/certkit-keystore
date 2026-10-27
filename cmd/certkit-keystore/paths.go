package main

import (
	"os"
	"path/filepath"

	keystoreInstall "github.com/certkit-io/certkit-keystore/install"
)

// devDirEnv names a folder where a dev build (one without a version stamped
// in, like `go run`) keeps its config, and on Windows its log, instead of the
// standard locations. run-local.ps1 sets it to run a keystore next to an
// installed one. Release builds ignore it.
const devDirEnv = "CERTKIT_KEYSTORE_DEV_DIR"

func devDir() string {
	if version != "dev" {
		return ""
	}
	return os.Getenv(devDirEnv)
}

// configPath is where the keystore's config is: always the standard
// location, except in dev builds.
func configPath() string {
	if dir := devDir(); dir != "" {
		return filepath.Join(dir, "config.json")
	}
	return keystoreInstall.ConfigPath
}
