package nmap

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/bijoian/cyberfusion/internal/domain"
	"github.com/sirupsen/logrus"
)

const (
	AdapterName = "nmap"
	Version     = "1.0.0"
)

// NmapAdapter wraps nmap for CyberFusion
type NmapAdapter struct {
	log *logrus.Logger
}

// New creates a new nmap adapter
func New(log *logrus.Logger) *NmapAdapter {
	return &NmapAdapter{
		log: log,
	}
}

// Name returns the adapter name
func (n *NmapAdapter) Name() string {
	return AdapterName
}

// Version returns the adapter version
func (n *NmapAdapter) Version() string {
	return Version
}

// SupportsProtocol checks if nmap supports a protocol
func (n *NmapAdapter) SupportsProtocol(protocol string) bool {
	protocols := map[string]bool{
		"tcp":  true,
		"udp":  true,
		"icmp": true,
	}
	return protocols[protocol]
}

// Scan executes nmap scan
func (n *NmapAdapter) Scan(ctx context.Context, target string, options map[string]interface{}) ([]domain.Finding, error) {
	if !n.isInstalled() {
		return nil, fmt.Errorf("nmap is not installed")
	}

	n.log.Infof("Running nmap scan on %s", target)

	// Execute nmap command
	cmd := exec.CommandContext(ctx, "nmap", "-sV", target)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nmap scan failed: %w", err)
	}

	// Parse output and convert to findings
	findings := n.parseOutput(string(output), target)
	return findings, nil
}

func (n *NmapAdapter) isInstalled() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

func (n *NmapAdapter) parseOutput(output string, target string) []domain.Finding {
	// TODO: Parse nmap output and create findings
	findings := []domain.Finding{}
	// Placeholder: Add actual parsing logic
	return findings
}
