package nmap

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/bijoian/cyberfusion/internal/domain"
)

// Scan executes an nmap scan on the target
func (n *NmapAdapter) Scan(ctx context.Context, target string, options map[string]interface{}) ([]domain.Finding, error) {
	if !n.isInstalled() {
		return nil, fmt.Errorf("nmap is not installed on this system")
	}

	n.log.Infof("Starting nmap scan on target: %s", target)

	// Build nmap command arguments
	args := n.buildNmapArgs(target, options)

	n.log.Debugf("Running: nmap %s", strings.Join(args, " "))

	// Execute nmap
	cmd := exec.CommandContext(ctx, "nmap", args...)

	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		// nmap returns exit code 1 when hosts are up, this is not an error
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 0 && exitErr.ExitCode() != 1 {
				n.log.Errorf("nmap execution failed with exit code %d", exitErr.ExitCode())
				return nil, fmt.Errorf("nmap scan failed: %w", err)
			}
		}
	}

	n.log.Debugf("nmap output:\n%s", string(output))

	// Parse output
	findings, err := n.ParseNmapOutput(string(output), target)
	if err != nil {
		n.log.Errorf("Failed to parse nmap output: %v", err)
		return nil, fmt.Errorf("failed to parse nmap output: %w", err)
	}

	n.log.Infof("Nmap scan completed: found %d findings", len(findings))

	return findings, nil
}

// buildNmapArgs constructs nmap command arguments
func (n *NmapAdapter) buildNmapArgs(target string, options map[string]interface{}) []string {
	args := []string{
		"-sV",                   // Service version detection
		"-sC",                   // Default scripts
		"--open",                // Only show open ports
		"-O",                    // OS detection
		"--version-intensity=9", // High accuracy version detection
	}

	// Add options if provided
	if timeout, ok := options["timeout"].(int); ok && timeout > 0 {
		args = append(args, fmt.Sprintf("--max-retries=%d", timeout))
	}

	if ports, ok := options["ports"].(string); ok && ports != "" {
		args = append(args, "-p", ports)
	} else {
		// Default: scan common ports
		args = append(args, "-p", "1-10000")
	}

	// Add aggressive scan option if requested
	if aggressive, ok := options["aggressive"].(bool); ok && aggressive {
		args = append(args, "-A") // Same as -sV -sC -O --traceroute
	}

	// Add target
	args = append(args, target)

	return args
}

// isInstalled checks if nmap is available in the system
func (n *NmapAdapter) isInstalled() bool {
	_, err := exec.LookPath("nmap")
	if err != nil {
		n.log.Warnf("nmap is not installed: %v", err)
		return false
	}
	return true
}

// GetVersion returns the installed nmap version
func (n *NmapAdapter) GetVersion() (string, error) {
	cmd := exec.Command("nmap", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}
