package main

import (
	"fmt"
	"log"
	"os"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreInstall "github.com/certkit-io/certkit-keystore/install"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func Version() config.VersionInfo {
	return config.VersionInfo{
		Version: version,
		Commit:  commit,
		Date:    buildDate,
	}
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.LUTC)

	if len(os.Args) < 2 {
		usageAndExit()
	}

	switch os.Args[1] {
	case "install":
		installCmd(os.Args[2:])
	case "uninstall":
		uninstallCmd(os.Args[2:])
	case "run":
		runCmd(os.Args[2:])
	default:
		usageAndExit()
	}
}

func usageAndExit() {
	fmt.Fprintf(os.Stderr, "Usage: certkit-keystore <command> [options]\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  install     Install as a system service\n")
	fmt.Fprintf(os.Stderr, "    --key           Registration key: {app_id}.{keystore_id} (or set CERTKIT_REGISTRATION_KEY)\n")
	fmt.Fprintf(os.Stderr, "    --host          Keystore hostname or IP (required)\n")
	fmt.Fprintf(os.Stderr, "    --config        Path to config file (default: %s)\n", keystoreInstall.DefaultConfigPath)
	fmt.Fprintf(os.Stderr, "    --port          Keystore listen port (default: %s)\n", config.DefaultKeystorePort)
	fmt.Fprintf(os.Stderr, "    --storage-dir   Directory for key storage (default: %s)\n", keystoreInstall.DefaultStorageDir)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  Examples:\n")
	fmt.Fprintf(os.Stderr, "    certkit-keystore install --key xdnt.4v93kfts --host keystore.example.com\n")
	fmt.Fprintf(os.Stderr, "    certkit-keystore install --key xdnt.4v93kfts --host 192.168.1.50 --port 8989\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  uninstall   Stop and remove the system service\n")
	fmt.Fprintf(os.Stderr, "    --config        Path to config file (default: %s)\n", keystoreInstall.DefaultConfigPath)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  run         Run in foreground (debug mode)\n")
	fmt.Fprintf(os.Stderr, "    --config        Path to config file (default: %s)\n", keystoreInstall.DefaultConfigPath)
	os.Exit(1)
}
