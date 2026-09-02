package nmap

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestParsePortLine(t *testing.T) {
	log := logrus.New()
	adapter := New(log)

	tests := []struct {
		name     string
		line     string
		wantPort int
		wantProto string
		wantState string
		wantErr  bool
	}{
		{
			name:      "SSH port",
			line:      "22/tcp   open  ssh     OpenSSH 7.4",
			wantPort: 22,
			wantProto: "tcp",
			wantState: "open",
			wantErr:  false,
		},
		{
			name:      "HTTP port",
			line:      "80/tcp   open  http    Apache httpd 2.4.6",
			wantPort: 80,
			wantProto: "tcp",
			wantState: "open",
			wantErr:  false,
		},
		{
			name:      "Closed port",
			line:      "3306/tcp closed mysql",
			wantPort: 3306,
			wantProto: "tcp",
			wantState: "closed",
			wantErr:  false,
		},
		{
			name:     "Invalid line",
			line:     "invalid line",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, err := adapter.parsePortLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePortLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if port.PortNumber != tt.wantPort {
					t.Errorf("parsePortLine() port = %d, want %d", port.PortNumber, tt.wantPort)
				}
				if port.Protocol != tt.wantProto {
					t.Errorf("parsePortLine() protocol = %s, want %s", port.Protocol, tt.wantProto)
				}
				if port.State != tt.wantState {
					t.Errorf("parsePortLine() state = %s, want %s", port.State, tt.wantState)
				}
			}
		})
	}
}

func TestDetermineSeverity(t *testing.T) {
	log := logrus.New()
	adapter := New(log)

	tests := []struct {
		name     string
		port     int
		wantSev  string
	}{
		{"Telnet", 23, "high"},
		{"MySQL", 3306, "high"},
		{"SSH", 22, "medium"},
		{"HTTP", 80, "medium"},
		{"HTTPS", 443, "medium"},
		{"High random port", 9999, "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := NmapPort{PortNumber: tt.port}
			got := adapter.determineSeverity(port)
			if got != tt.wantSev {
				t.Errorf("determineSeverity() = %s, want %s", got, tt.wantSev)
			}
		})
	}
}

func TestParseNmapOutput(t *testing.T) {
	log := logrus.New()
	adapter := New(log)

	nmapOutput := `Starting Nmap 7.92
Nmap scan report for example.com (192.168.1.1)
Host is up (0.0023s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4
80/tcp   open  http    Apache httpd 2.4.6
443/tcp  open  https   nginx 1.14.0
3306/tcp open  mysql   MySQL 5.7.31

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done at Mon Sep  2 02:40:00 2026; 1 IP address (1 host up) scanned in 5.23 seconds
`

	findings, err := adapter.ParseNmapOutput(nmapOutput, "192.168.1.1")
	if err != nil {
		t.Fatalf("ParseNmapOutput() error = %v", err)
	}

	if len(findings) < 4 {
		t.Errorf("ParseNmapOutput() returned %d findings, want at least 4", len(findings))
	}

	// Check for SSH finding
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "22") {
			found = true
			if f.Severity != "medium" {
				t.Errorf("SSH finding severity = %s, want medium", f.Severity)
			}
		}
	}
	if !found {
		t.Error("No finding for SSH port 22")
	}
}
