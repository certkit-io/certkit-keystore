package install

import "testing"

func TestValidateFirewallPort(t *testing.T) {
	tests := []struct {
		name    string
		port    string
		wantErr bool
	}{
		{"default https", "443", false},
		{"high port", "8443", false},
		{"min", "1", false},
		{"max", "65535", false},
		{"zero", "0", true},
		{"over range", "65536", true},
		{"negative", "-1", true},
		{"empty", "", true},
		{"non numeric", "abc", true},
		{"trailing tcp", "443/tcp", true},
		{"injection attempt", "443; rm -rf /", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFirewallPort(tt.port)
			if tt.wantErr && err == nil {
				t.Errorf("validateFirewallPort(%q) = nil, want error", tt.port)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateFirewallPort(%q) = %v, want nil", tt.port, err)
			}
		})
	}
}
