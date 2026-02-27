package proxy

import (
	"testing"
)

func TestValidateHost(t *testing.T) {
	tests := []struct {
		host    string
		wantErr bool
	}{
		// Alternative encodings → rejected
		{"0x7f000001", true},
		{"2130706433", true},
		{"0177.0.0.1", true},
		// Blocked IPs → rejected
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		// Normal domains → pass
		{"example.com", false},
		{"api.github.com", false},
		// Public IPs → pass
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		err := ValidateHost(tt.host)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateHost(%q) error=%v, wantErr=%v", tt.host, err, tt.wantErr)
		}
	}
}
