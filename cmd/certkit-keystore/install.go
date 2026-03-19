package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreInstall "github.com/certkit-io/certkit-keystore/install"
)

// promptRequired prompts the user for a mandatory value. If a value was already
// provided via flag it is used as-is; otherwise the user is prompted repeatedly
// until a non-empty value is entered.
func promptRequired(reader *bufio.Reader, label string, flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	for {
		fmt.Printf("%s: ", label)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input != "" {
			return input
		}
		fmt.Println("  This field is required.")
	}
}

// promptOptional prompts the user for an optional value, showing the default.
// Pressing enter accepts the default. If a non-default value was already provided
// via flag it is used as-is.
func promptOptional(reader *bufio.Reader, label string, flagVal string, defaultVal string) string {
	if flagVal != defaultVal {
		return flagVal
	}
	fmt.Printf("%s [%s]: ", label, defaultVal)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

func installCmd(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	key := fs.String("key", "", "registration key in format {app_id}.{keystore_id} (or set CERTKIT_REGISTRATION_KEY)")
	configPath := fs.String("config", keystoreInstall.DefaultConfigPath, "path to config file")
	host := fs.String("host", "", "keystore hostname or IP (e.g. keystore.example.com or 192.168.1.50)")
	port := fs.String("port", config.DefaultKeystorePort, "keystore listen port")
	storageDir := fs.String("storage-dir", keystoreInstall.DefaultStorageDir, "directory for key storage")
	fs.Parse(args)

	v := Version()
	log.Printf("certkit-keystore %s (commit: %s, built: %s)", v.Version, v.Commit, v.Date)

	// If a config already exists and has been initialized, skip creation
	existing, err := config.ReadConfig(*configPath)
	if err == nil && existing.Keystore != nil && existing.Keystore.Initialized {
		log.Printf("Config at %s is already initialized, skipping configuration", *configPath)
	} else {
		reader := bufio.NewReader(os.Stdin)

		// Allow env var fallback for key before prompting
		keyVal := *key
		if keyVal == "" {
			keyVal = os.Getenv("CERTKIT_REGISTRATION_KEY")
		}

		fmt.Println()
		keyVal = promptRequired(reader, "Registration key (abc.xyz123)", keyVal)
		*storageDir = promptOptional(reader, "Storage directory", *storageDir, keystoreInstall.DefaultStorageDir)
		*host = promptRequired(reader, "Host (hostname or IP)", *host)
		*port = promptOptional(reader, "Port", *port, config.DefaultKeystorePort)
		*configPath = promptOptional(reader, "Config file path", *configPath, keystoreInstall.DefaultConfigPath)
		fmt.Println()

		if err := config.CreateInitialConfig(*configPath, keyVal, *host, *port, *storageDir); err != nil {
			log.Fatalf("Install failed: %v", err)
		}
		log.Printf("Config written to %s", *configPath)
	}

	keystoreInstall.InstallService(*configPath)
}
