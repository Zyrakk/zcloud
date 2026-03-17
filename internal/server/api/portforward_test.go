package api

import "testing"

func TestValidatePortForwardTarget(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"localhost allowed", "localhost", false},
		{"loopback allowed", "127.0.0.1", false},
		{"k8s service allowed", "my-svc.default.svc.cluster.local", false},
		{"k8s pod allowed", "10.42.1.5", false},
		{"metadata IP blocked", "169.254.169.254", true},
		{"google metadata DNS blocked", "metadata.google.internal", true},
		{"link-local start blocked", "169.254.0.1", true},
		{"link-local end blocked", "169.254.255.255", true},
		{"unspecified blocked", "0.0.0.0", true},
		{"ipv6 unspecified blocked", "::", true},
		{"ipv6 loopback blocked", "::1", true},
		{"ipv6 link-local blocked", "fe80::1", true},
		{"ipv6 ULA blocked", "fd00::1", true},
		{"ipv4-mapped v6 link-local blocked", "::ffff:169.254.169.254", true},
		{"arbitrary hostname blocked", "evil.com", true},
		{"empty host blocked", "", true},
		{"loopback 127.0.0.2 blocked", "127.0.0.2", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePortForwardTarget(tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePortForwardTarget(%q) error = %v, wantErr %v", tt.host, err, tt.wantErr)
			}
		})
	}
}
