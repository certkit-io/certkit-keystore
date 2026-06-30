//go:build windows

package utils

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// RunPowerShellLogged runs a PowerShell script and logs any output, mirroring
// the shell-out pattern used for other Windows host operations. It is the
// preferred way to invoke PowerShell from install/maintenance code.
func RunPowerShellLogged(script string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if out.Len() > 0 {
		log.Printf("Ran PowerShell: %s\n%s", script, strings.TrimSpace(out.String()))
	}
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}
