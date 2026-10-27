//go:build !windows

package install

import (
	"strings"
	"testing"
)

func TestSystemdUnitRunsTheKeystoreWithoutAConfigPath(t *testing.T) {
	unit := renderSystemdUnit("/usr/local/bin/certkit-keystore")
	if !strings.Contains(unit, "\nExecStart=\"/usr/local/bin/certkit-keystore\" run\n") {
		t.Fatalf("unit = %s\nwant ExecStart to run the keystore with no arguments", unit)
	}
}
