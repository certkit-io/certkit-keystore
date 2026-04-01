package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	keystoreInstall "github.com/certkit-io/certkit-keystore/install"
)

func uninstallCmd(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	configPath := fs.String("config", keystoreInstall.DefaultConfigPath, "path to config file")
	fs.Parse(args)

	fmt.Println()
	fmt.Println("This will stop and remove the certkit-keystore service.")
	fmt.Printf("The configuration file (%s) will also be removed.\n", *configPath)
	fmt.Println("Stored certificates will NOT be removed.")
	fmt.Println()
	fmt.Print("Continue? (y/N): ")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	if answer != "y" && answer != "yes" {
		fmt.Println("Uninstall cancelled.")
		return
	}

	fmt.Println()
	keystoreInstall.UninstallService()

	if err := os.Remove(*configPath); err != nil {
		if os.IsNotExist(err) {
			log.Printf("No config file found at %s; skipping", *configPath)
		} else {
			log.Fatalf("failed to remove config file %s: %v", *configPath, err)
		}
	} else {
		log.Printf("Removed config file %s", *configPath)
	}
}
