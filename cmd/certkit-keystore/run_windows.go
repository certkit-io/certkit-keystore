//go:build windows

package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	keystoreInstall "github.com/certkit-io/certkit-keystore/install"
	"golang.org/x/sys/windows/svc"
)

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", keystoreInstall.DefaultConfigPath, "path to config file")
	forceService := fs.Bool("service", false, "force service mode (used by SCM)")
	fs.Parse(args)

	isService, err := svc.IsWindowsService()

	if *forceService || (err == nil && isService) {
		log.Printf("Running as Windows service...")
		runWindowsService(*configPath)
		return
	}

	// Foreground mode
	setLogOutputWithEventLog(os.Stdout)

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %s, shutting down", sig)
		close(stopCh)
	}()

	runKeystore(*configPath, stopCh)
}

func runWindowsService(configPath string) {
	if err := svc.Run(keystoreInstall.ServiceName, &windowsService{configPath: configPath}); err != nil {
		log.Fatalf("service failed: %v", err)
	}
}

type windowsService struct {
	configPath string
}

func (s *windowsService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	initServiceLogging(s.configPath)

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		runKeystore(s.configPath, stopCh)
		close(done)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			close(stopCh)
			<-done
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		default:
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	close(stopCh)
	<-done
	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

const (
	maxLogSize = 5 * 1024 * 1024
	keepLines  = 10000
)

func initServiceLogging(configPath string) {
	logFile := filepath.Join(filepath.Dir(configPath), "certkit-keystore.log")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	setLogOutputWithEventLog(f)
	go logTruncator(logFile, f)
}

func logTruncator(logFile string, current *os.File) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		info, err := current.Stat()
		if err != nil || info.Size() < maxLogSize {
			continue
		}
		data, err := os.ReadFile(logFile)
		if err != nil {
			continue
		}
		lines := bytes.Split(data, []byte("\n"))
		if len(lines) <= keepLines {
			continue
		}
		kept := bytes.Join(lines[len(lines)-keepLines:], []byte("\n"))

		if err := os.WriteFile(logFile, kept, 0o644); err != nil {
			continue
		}
		newFile, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			continue
		}
		setLogOutputWithEventLog(newFile)
		old := current
		current = newFile
		old.Close()
	}
}
