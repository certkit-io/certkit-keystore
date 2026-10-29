//go:build !windows

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	// Services installed by earlier versions still pass the config's path.
	fs.String("config", "", "unused: the config is always at the standard path")
	fs.Parse(args)

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %s, shutting down", sig)
		close(stopCh)
	}()

	runKeystore(configPath(), stopCh)
}
