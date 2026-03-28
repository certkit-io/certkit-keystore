package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreInstall "github.com/certkit-io/certkit-keystore/install"
)

// scanLine reads one line from the scanner, trimming whitespace.
func scanLine(scanner *bufio.Scanner) string {
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

// promptRequired prompts the user for a mandatory value. If a value was already
// provided via flag it is used as-is; otherwise the user is prompted repeatedly
// until a non-empty value is entered.
func promptRequired(scanner *bufio.Scanner, label string, flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	for {
		fmt.Printf("%s: ", label)
		input := scanLine(scanner)
		if input != "" {
			return input
		}
		fmt.Println("  This field is required.")
	}
}

// promptOptional prompts the user for an optional value, showing the default.
// Pressing enter accepts the default. If a non-default value was already provided
// via flag it is used as-is.
func promptOptional(scanner *bufio.Scanner, label string, flagVal string, defaultVal string) string {
	if flagVal != defaultVal {
		return flagVal
	}
	fmt.Printf("%s [%s]: ", label, defaultVal)
	input := scanLine(scanner)
	if input == "" {
		return defaultVal
	}
	return input
}

// validateHost checks that the given hostname or IP belongs to this machine by
// comparing against local interface addresses, the OS hostname, and DNS resolution.
func validateHost(input string) error {
	hostname, _ := os.Hostname()

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil // can't enumerate interfaces, skip check
	}

	var localIPs []string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			localIPs = append(localIPs, ipNet.IP.String())
		}
	}

	// Direct match against OS hostname
	if strings.EqualFold(input, hostname) {
		return nil
	}

	// Direct match against a local IP
	for _, ip := range localIPs {
		if input == ip {
			return nil
		}
	}

	// Try DNS resolution to see if it points to a local address
	resolved, resolveErr := net.LookupHost(input)
	if resolveErr == nil {
		for _, r := range resolved {
			for _, ip := range localIPs {
				if r == ip {
					return nil
				}
			}
		}
	}

	// Build a readable hint list (skip loopback and link-local for clarity)
	var hints []string
	if hostname != "" {
		hints = append(hints, hostname)
	}
	for _, ip := range localIPs {
		parsed := net.ParseIP(ip)
		if parsed != nil && !parsed.IsLoopback() && !parsed.IsLinkLocalUnicast() {
			hints = append(hints, ip)
		}
	}
	return fmt.Errorf("'%s' does not appear to belong to this machine.\n  This machine's identities: %s", input, strings.Join(hints, ", "))
}

// validatePort checks that the port string is a valid number between 1 and 65535.
func validatePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("'%s' is not a valid number", port)
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("%d is out of range (must be 1-65535)", n)
	}
	return nil
}

// checkPortInUse returns a non-nil error if something is already listening on the port.
func checkPortInUse(host, port string) error {
	addr := net.JoinHostPort(host, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("port %s appears to be in use on %s", port, host)
	}
	ln.Close()
	return nil
}

// validateStorageDir checks that the path is absolute and, if it already exists,
// that it is a directory rather than a regular file. Returns "missing" (true) when
// the path does not exist so the caller can confirm with the user.
func validateStorageDir(dir string) (missing bool, err error) {
	if !filepath.IsAbs(dir) {
		return false, fmt.Errorf("must be an absolute path (e.g. %s)", keystoreInstall.DefaultStorageDir)
	}
	info, statErr := os.Stat(dir)
	if statErr == nil {
		if !info.IsDir() {
			return false, fmt.Errorf("'%s' exists but is not a directory", dir)
		}
		return false, nil
	}
	return true, nil
}

func installCmd(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	key := fs.String("key", "", "registration key in format {app_id}.{keystore_id} (or set CERTKIT_REGISTRATION_KEY)")
	configPath := fs.String("config", keystoreInstall.DefaultConfigPath, "path to config file")
	host := fs.String("host", "", "keystore hostname or IP (e.g. keystore.example.com or 192.168.1.50)")
	port := fs.String("port", config.DefaultKeystorePort, "keystore listen port")
	storageDir := fs.String("storage-dir", keystoreInstall.DefaultStorageDir, "directory for key storage")
	noService := fs.Bool("no-service", os.Getenv("KEYSTORE_NO_SERVICE") != "", "skip service creation/update")
	fs.Parse(args)

	v := Version()
	log.Printf("certkit-keystore %s (commit: %s, built: %s)", v.Version, v.Commit, v.Date)

	// If a config already exists and has been initialized, skip creation
	existing, err := config.ReadConfig(*configPath)
	if err == nil && existing.Keystore != nil && existing.Keystore.Initialized {
		log.Printf("Config at %s is already initialized, skipping configuration", *configPath)
	} else {
		scanner := bufio.NewScanner(os.Stdin)

		// Allow env var fallback for key before prompting
		keyVal := *key
		if keyVal == "" {
			keyVal = os.Getenv("CERTKIT_REGISTRATION_KEY")
		}

		// Gate prompt: absorb any stray newlines from pasted curl-bash commands
		fmt.Println()
		fmt.Print("Press Enter to begin configuration...")
		scanLine(scanner)

		for {
			fmt.Println()
			keyVal = promptRequired(scanner, "Registration key (abc.xyz123)", keyVal)
			if _, _, err := config.ParseRegistrationKey(keyVal); err != nil {
				fmt.Printf("  Invalid registration key: %s\n", err)
				fmt.Print("  Press Enter to start over...")
				scanLine(scanner)
				keyVal = ""
				*host = ""
				*port = config.DefaultKeystorePort
				*storageDir = keystoreInstall.DefaultStorageDir
				continue
			}
			*host = promptRequired(scanner, "Host (hostname or IP)", *host)
			if err := validateHost(*host); err != nil {
				fmt.Printf("  Warning: %s\n", err)
				fmt.Print("  Use this value anyway? (y/N): ")
				confirm := strings.ToLower(scanLine(scanner))
				if confirm != "y" && confirm != "yes" {
					fmt.Println("  Starting over...")
					keyVal = ""
					*host = ""
					*port = config.DefaultKeystorePort
					*storageDir = keystoreInstall.DefaultStorageDir
					continue
				}
			}
			*port = promptOptional(scanner, "Port", *port, config.DefaultKeystorePort)
			if err := validatePort(*port); err != nil {
				fmt.Printf("  Invalid port: %s\n", err)
				fmt.Print("  Press Enter to start over...")
				scanLine(scanner)
				keyVal = ""
				*host = ""
				*port = config.DefaultKeystorePort
				*storageDir = keystoreInstall.DefaultStorageDir
				continue
			}
			if err := checkPortInUse(*host, *port); err != nil {
				fmt.Printf("  Warning: %s\n", err)
				fmt.Print("  Use this port anyway? (y/N): ")
				confirm := strings.ToLower(scanLine(scanner))
				if confirm != "y" && confirm != "yes" {
					fmt.Println("  Starting over...")
					keyVal = ""
					*host = ""
					*port = config.DefaultKeystorePort
					*storageDir = keystoreInstall.DefaultStorageDir
					continue
				}
			}
			*storageDir = promptOptional(scanner, "Storage directory", *storageDir, keystoreInstall.DefaultStorageDir)
			dirMissing, dirErr := validateStorageDir(*storageDir)
			if dirErr != nil {
				fmt.Printf("  Invalid storage directory: %s\n", dirErr)
				fmt.Print("  Press Enter to start over...")
				scanLine(scanner)
				keyVal = ""
				*host = ""
				*port = config.DefaultKeystorePort
				*storageDir = keystoreInstall.DefaultStorageDir
				continue
			}
			if dirMissing {
				fmt.Printf("  '%s' does not exist. It will be created during install.\n", *storageDir)
				fmt.Print("  Continue? (Y/n): ")
				confirm := strings.ToLower(scanLine(scanner))
				if confirm == "n" || confirm == "no" {
					fmt.Println("  Starting over...")
					keyVal = ""
					*host = ""
					*port = config.DefaultKeystorePort
					*storageDir = keystoreInstall.DefaultStorageDir
					continue
				}
			}
			// TODO: may re-enable config path prompt
			// *configPath = promptOptional(scanner, "Config file path", *configPath, keystoreInstall.DefaultConfigPath)

			fmt.Println()
			fmt.Println("Configuration summary:")
			fmt.Printf("  Registration key:   %s\n", keyVal)
			fmt.Printf("  Host:               %s\n", *host)
			fmt.Printf("  Port:               %s\n", *port)
			fmt.Printf("  Storage directory:   %s\n", *storageDir)
			fmt.Printf("  Config file:         %s\n", *configPath)
			fmt.Println()
			fmt.Print("Accept? [Y]es / [n]o / [r]estart: ")
			choice := strings.ToLower(scanLine(scanner))

			if choice == "" || choice == "y" || choice == "yes" {
				break
			}
			if choice == "n" || choice == "no" {
				fmt.Println("Installation cancelled.")
				os.Exit(0)
			}
			// Any other input (including "r") restarts prompts
			fmt.Println("Starting over...")
			keyVal = ""
			*host = ""
			*port = config.DefaultKeystorePort
			*storageDir = keystoreInstall.DefaultStorageDir
		}
		fmt.Println()

		if err := config.CreateInitialConfig(*configPath, keyVal, *host, *port, *storageDir, keystoreInstall.ServiceName); err != nil {
			log.Fatalf("Install failed: %v", err)
		}
		log.Printf("Config written to %s", *configPath)
	}

	if *noService {
		log.Println("Skipping service install (--no-service)")
	} else {
		keystoreInstall.InstallService(*configPath)
	}
}
