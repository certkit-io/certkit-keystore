//go:build windows

package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/certkit-io/certkit-keystore/config"
	keystoreInstall "github.com/certkit-io/certkit-keystore/install"
	"golang.org/x/sys/windows/svc"
)

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	// Services installed by earlier versions still pass the config's path.
	fs.String("config", "", "unused: the config is always at the standard path")
	forceService := fs.Bool("service", false, "force service mode (used by SCM)")
	fs.Parse(args)

	isService, err := svc.IsWindowsService()

	if *forceService || (err == nil && isService) {
		log.Printf("Running as Windows service...")
		runWindowsService(configPath())
		return
	}

	// Foreground mode
	initLogFile(logPath(), os.Stdout)

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %s, shutting down", sig)
		close(stopCh)
	}()

	runKeystore(configPath(), stopCh)
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

	initLogFile(logPath(), io.Discard)

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

// logPath is the log file, next to the config: in the standard location,
// except in dev builds.
func logPath() string {
	if dir := devDir(); dir != "" {
		return filepath.Join(dir, "certkit-keystore.log")
	}
	return keystoreInstall.LogPath
}

// initLogFile sends the log to console and to logFile, which the status
// page's logs page shows. If the file can't be opened, the log goes to
// console only.
func initLogFile(logFile string, console io.Writer) {
	config.CurrentLogPath = logFile
	f, err := openLogFile(logFile)
	if err != nil {
		setLogOutputWithEventLog(console)
		log.Printf("Not writing a log file: %v", err)
		return
	}
	setLogOutputWithEventLog(io.MultiWriter(console, f))
	go logTruncator(logFile, f, console)
}

func openLogFile(logFile string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(logFile), 0o755); err != nil {
		return nil, err
	}
	return os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
}

func logTruncator(logFile string, current *os.File, console io.Writer) {
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
		setLogOutputWithEventLog(io.MultiWriter(console, newFile))
		old := current
		current = newFile
		old.Close()
	}
}
