package nmap

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bijoian/cyberfusion/internal/domain"
)

// NmapResult represents parsed nmap output
type NmapResult struct {
	Host        string
	Status      string
	Ports       []NmapPort
	OS          string
	OSVersion   string
	Fingerprint string
}

// NmapPort represents a single port from nmap output
type NmapPort struct {
	PortNumber int
	Protocol   string
	State      string
	Service    string
	Version    string
	Banner     string
}

// ParseNmapOutput parses nmap command output
func (n *NmapAdapter) ParseNmapOutput(output string, target string) ([]domain.Finding, error) {
	result := &NmapResult{
		Host:  target,
		Ports: []NmapPort{},
	}

	findings := []domain.Finding{}

	lines := strings.Split(output, "\n")

	// Parse port information
	for i, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "Nmap") || strings.HasPrefix(line, "Starting") {
			continue
		}

		// Parse port line: "22/tcp   open  ssh     OpenSSH 7.4"
		if strings.Contains(line, "tcp") || strings.Contains(line, "udp") {
			port, err := n.parsePortLine(line)
			if err == nil {
				result.Ports = append(result.Ports, port)

				// Create finding for this port
				finding := n.createPortFinding(target, port)
				findings = append(findings, *finding)
			}
		}

		// Parse OS detection
		if strings.Contains(line, "Running:") {
			result.OS = strings.TrimPrefix(line, "Running:")
		}

		// Check for service vulnerabilities
		if len(result.Ports) > 0 {
			lastPort := result.Ports[len(result.Ports)-1]
			vulnFindings := n.checkServiceVulnerabilities(target, lastPort)
			findings = append(findings, vulnFindings...)
		}

		_ = i // silence unused warning
	}

	if len(result.Ports) == 0 {
		n.log.Warnf("No open ports found for %s", target)
		// Create an info finding
		infoFinding := domain.NewFinding()
		infoFinding.AssetID = target
		infoFinding.FindingType = "info"
		infoFinding.Title = "Host Scan Completed"
		infoFinding.Description = fmt.Sprintf("Scan completed on %s - No open ports detected", target)
		infoFinding.Severity = "info"
		infoFinding.Confidence = 100
		infoFinding.Status = "open"
		infoFinding.Sources = []string{"nmap"}
		findings = append(findings, *infoFinding)
	}

	return findings, nil
}

func (n *NmapAdapter) parsePortLine(line string) (NmapPort, error) {
	port := NmapPort{}

	// Split by whitespace, handling multiple spaces
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return port, fmt.Errorf("invalid port line: %s", line)
	}

	// Parse port/protocol (e.g., "22/tcp")
	portProto := strings.Split(fields[0], "/")
	if len(portProto) != 2 {
		return port, fmt.Errorf("invalid port format: %s", fields[0])
	}

	portNum, err := strconv.Atoi(portProto[0])
	if err != nil {
		return port, fmt.Errorf("invalid port number: %s", portProto[0])
	}

	port.PortNumber = portNum
	port.Protocol = portProto[1]
	port.State = fields[1]

	if len(fields) > 2 {
		port.Service = fields[2]
	}

	// Version info starts after service name
	if len(fields) > 3 {
		port.Version = strings.Join(fields[3:], " ")
		port.Banner = port.Version
	}

	return port, nil
}

func (n *NmapAdapter) createPortFinding(target string, port NmapPort) *domain.Finding {
	finding := domain.NewFinding()
	finding.AssetID = target
	finding.FindingType = "open_port"
	finding.Title = fmt.Sprintf("Open Port Detected: %d/%s", port.PortNumber, port.Protocol)
	finding.Description = fmt.Sprintf(
		"Port %d/%s is open and running %s\nVersion: %s",
		port.PortNumber, port.Protocol, port.Service, port.Version,
	)
	finding.Evidence = fmt.Sprintf(
		"nmap detected %d/%s in state %s with service %s",
		port.PortNumber, port.Protocol, port.State, port.Service,
	)
	finding.Confidence = 95
	finding.Status = "open"
	finding.Sources = []string{"nmap"}

	// Determine severity based on port and service
	finding.Severity = n.determineSeverity(port)

	// Add remediation advice
	finding.Remediation = n.getRemediationAdvice(port)

	return finding
}

func (n *NmapAdapter) determineSeverity(port NmapPort) string {
	// High-risk ports
	highRiskPorts := map[int]bool{
		23:   true, // Telnet
		69:   true, // TFTP
		135:  true, // RPC
		139:  true, // NetBIOS
		445:  true, // SMB
		1433: true, // MSSQL
		3306: true, // MySQL
		5432: true, // PostgreSQL
		6379: true, // Redis
		9200: true, // Elasticsearch
	}

	if highRiskPorts[port.PortNumber] {
		return "high"
	}

	// Medium-risk ports
	mediumRiskPorts := map[int]bool{
		80:  true, // HTTP
		443: true, // HTTPS
		22:  true, // SSH
		25:  true, // SMTP
		53:  true, // DNS
		110: true, // POP3
		143: true, // IMAP
		587: true, // SMTP TLS
	}

	if mediumRiskPorts[port.PortNumber] {
		return "medium"
	}

	return "low"
}

func (n *NmapAdapter) getRemediationAdvice(port NmapPort) string {
	remediations := map[int]string{
		23:   "Close Telnet port. Use SSH instead (port 22)",
		69:   "Disable TFTP. Use SFTP or SCP for file transfer",
		135:  "Disable RPC or restrict to trusted networks",
		139:  "Disable NetBIOS or restrict to internal networks",
		445:  "Implement SMB signing and disable if not needed",
		1433: "Change default SQL Server port, use strong authentication",
		3306: "Change default MySQL port, disable root remote login",
		5432: "Change default PostgreSQL port, use strong authentication",
		6379: "Enable Redis authentication and restrict network access",
		9200: "Restrict Elasticsearch to internal networks only",
		80:   "Enforce HTTPS. Redirect HTTP to HTTPS",
		443:  "Update to latest TLS version. Use strong ciphers",
		22:   "Disable password auth. Use SSH keys. Change default port",
		25:   "Implement authentication. Use TLS for SMTP",
		53:   "Implement DNSSEC. Disable zone transfers",
	}

	if advice, ok := remediations[port.PortNumber]; ok {
		return advice
	}

	return "Review service configuration and apply security best practices"
}

func (n *NmapAdapter) checkServiceVulnerabilities(target string, port NmapPort) []domain.Finding {
	var findings []domain.Finding

	// Check for known vulnerable services
	vulnerabilities := map[string]map[string][]string{
		"ssh": {
			"OpenSSH 7.4": []string{"CVE-2018-15473"},
			"OpenSSH 6.6": []string{"CVE-2018-15473"},
		},
		"http": {
			"Apache 2.4.6": []string{"CVE-2021-30641"},
			"nginx 1.14.0": []string{"CVE-2019-9511"},
		},
		"mysql": {
			"MySQL 5.7.31": []string{"CVE-2021-2109"},
		},
	}

	if vulns, ok := vulnerabilities[port.Service]; ok {
		for version, cves := range vulns {
			if strings.Contains(port.Version, version) {
				for _, cve := range cves {
					finding := domain.NewFinding()
					finding.AssetID = target
					finding.FindingType = "vulnerability"
					finding.Title = fmt.Sprintf("%s - %s", port.Service, cve)
					finding.Description = fmt.Sprintf(
						"Known vulnerability detected in %s %s\nCVE: %s",
						port.Service, version, cve,
					)
					finding.Severity = "high"
					finding.Confidence = 85
					finding.Status = "open"
					finding.Sources = []string{"nmap", "cve_database"}
					finding.FirstSeen = time.Now()
					finding.LastSeen = time.Now()
					findings = append(findings, *finding)
				}
			}
		}
	}

	return findings
}
