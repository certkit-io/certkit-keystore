//go:build !windows

package main

import "log"

func bootstrapConfigCmd(_ []string) {
	log.Fatal("bootstrap-config is only supported on Windows (used by the MSI installer)")
}

func msiCleanupCmd(_ []string) {
	log.Fatal("msi-cleanup is only supported on Windows (used by the MSI installer)")
}
