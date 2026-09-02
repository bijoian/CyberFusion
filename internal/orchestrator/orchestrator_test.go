package orchestrator

import (
	"context"
	"testing"

	"github.com/bijoian/cyberfusion/internal/domain"
	"github.com/bijoian/cyberfusion/internal/integration"
	"github.com/bijoian/cyberfusion/internal/integration/nuclei"
	"github.com/sirupsen/logrus"
)

func TestNucleiModuleIsOptIn(t *testing.T) {
	scanner := &recordingScanner{}
	registry := integration.NewRegistry()
	registry.Register(scanner)
	orchestrator := &Orchestrator{log: logrus.New(), registry: registry}

	findings, err := orchestrator.runVulnerabilityScans(context.Background(), ScanConfig{
		Targets: []string{"https://example.test"},
		Modules: []string{"port_scan", "service_detection"},
	})
	if err != nil {
		t.Fatalf("runVulnerabilityScans() error = %v", err)
	}
	if len(findings) != 0 || len(scanner.targets) != 0 {
		t.Fatalf("default modules unexpectedly invoked Nuclei: findings=%d calls=%d", len(findings), len(scanner.targets))
	}

	findings, err = orchestrator.runVulnerabilityScans(context.Background(), ScanConfig{
		Targets: []string{"https://example.test"},
		Modules: []string{"nuclei"},
	})
	if err != nil {
		t.Fatalf("runVulnerabilityScans() error = %v", err)
	}
	if len(findings) != 1 || len(scanner.targets) != 1 || scanner.targets[0] != "https://example.test" {
		t.Fatalf("Nuclei module was not invoked for its explicit target: findings=%d targets=%#v", len(findings), scanner.targets)
	}
}

type recordingScanner struct {
	targets []string
}

func (s *recordingScanner) Name() string {
	return nuclei.AdapterName
}

func (s *recordingScanner) Version() string {
	return "test"
}

func (s *recordingScanner) SupportsProtocol(string) bool {
	return true
}

func (s *recordingScanner) Scan(_ context.Context, target string, _ map[string]interface{}) ([]domain.Finding, error) {
	s.targets = append(s.targets, target)
	return []domain.Finding{{Title: "test finding"}}, nil
}
