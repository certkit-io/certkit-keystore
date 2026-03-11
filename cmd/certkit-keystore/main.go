package main

import (
	"fmt"
	"log"
	"os"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.LUTC)

	if len(os.Args) < 2 {
		usageAndExit()
	}

	switch os.Args[1] {
	case "install":
		installCmd(os.Args[2:])
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
	fmt.Fprintf(os.Stderr, "    --config        Path to config file (default: config.json)\n")
	fmt.Fprintf(os.Stderr, "    --port          Keystore listen port (default: 8989)\n")
	fmt.Fprintf(os.Stderr, "    --storage-dir   Directory for key storage (default: ./)\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  run         Run in foreground (debug mode)\n")
	fmt.Fprintf(os.Stderr, "    --config        Path to config file (default: config.json)\n")
	os.Exit(1)
}
