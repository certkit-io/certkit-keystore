//go:build !windows

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	keystoreInstall "github.com/certkit-io/certkit-keystore/install"
)

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", keystoreInstall.DefaultConfigPath, "path to config file")
	fs.Parse(args)

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %s, shutting down", sig)
		close(stopCh)
	}()

	runKeystore(*configPath, stopCh)
}
