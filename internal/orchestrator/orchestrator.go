package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bijoian/cyberfusion/internal/domain"
	"github.com/bijoian/cyberfusion/internal/integration"
	"github.com/bijoian/cyberfusion/internal/integration/nuclei"
	"github.com/sirupsen/logrus"
)

// Orchestrator manages the scan workflow
type Orchestrator struct {
	log      *logrus.Logger
	registry *integration.Registry
}

// New creates a new orchestrator
func New(log *logrus.Logger) *Orchestrator {
	registry := integration.NewRegistry()
	registry.Register(nuclei.New(log))

	return &Orchestrator{log: log, registry: registry}
}

// ScanConfig holds scan configuration
type ScanConfig struct {
	Targets   []string
	Modules   []string
	Timeout   time.Duration
	Threads   int
	ProxyURL  string
	UserAgent string
}

// ScanResult holds scan results
type ScanResult struct {
	Scan     *domain.Scan
	Assets   []domain.Asset
	Findings []domain.Finding
	Error    error
}

// ExecuteScan runs a scan with the given configuration
func (o *Orchestrator) ExecuteScan(ctx context.Context, config ScanConfig) (*ScanResult, error) {
	if len(config.Targets) == 0 {
		return nil, fmt.Errorf("no targets specified")
	}

	// Create scan record
	scan := domain.NewScan()
	scan.Targets = config.Targets
	scan.Status = "running"
	startTime := time.Now()
	scan.StartedAt = &startTime

	o.log.Infof("Starting scan %s with targets: %v", scan.ID, config.Targets)

	// This is the orchestrator pipeline
	result := &ScanResult{
		Scan:     scan,
		Assets:   []domain.Asset{},
		Findings: []domain.Finding{},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Phase 1: Discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.log.Infof("[%s] Phase 1: Discovery", scan.ID)
		assets, err := o.runDiscovery(ctx, config)
		if err != nil {
			o.log.Errorf("[%s] Discovery failed: %v", scan.ID, err)
			return
		}
		mu.Lock()
		result.Assets = append(result.Assets, assets...)
		mu.Unlock()
	}()

	wg.Wait()

	// Phase 2: Port Scanning
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.log.Infof("[%s] Phase 2: Port Scanning", scan.ID)
		// Port scan logic here
	}()

	wg.Wait()

	var vulnerabilityErr error

	// Phase 3: Vulnerability Scanning
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.log.Infof("[%s] Phase 3: Vulnerability Scanning", scan.ID)
		findings, err := o.runVulnerabilityScans(ctx, config)
		if err != nil {
			o.log.Errorf("[%s] Vulnerability scanning failed: %v", scan.ID, err)
			vulnerabilityErr = err
			return
		}
		mu.Lock()
		result.Findings = append(result.Findings, findings...)
		mu.Unlock()
	}()

	wg.Wait()
	if vulnerabilityErr != nil {
		scan.Status = "failed"
		return nil, fmt.Errorf("vulnerability scanning failed: %w", vulnerabilityErr)
	}

	// Phase 4: Correlation
	o.log.Infof("[%s] Phase 4: Correlation", scan.ID)
	o.correlateFindings(result)

	// Phase 5: Risk Analysis
	o.log.Infof("[%s] Phase 5: Risk Analysis", scan.ID)
	riskScore := o.calculateRiskScore(result)
	scan.RiskScore = riskScore

	// Mark scan as complete
	now := time.Now()
	scan.CompletedAt = &now
	scan.Duration = int64(now.Sub(startTime).Seconds())
	scan.Status = "completed"

	o.log.Infof("Scan %s completed in %d seconds with risk score: %d", scan.ID, scan.Duration, riskScore)

	return result, nil
}

func (o *Orchestrator) runDiscovery(ctx context.Context, config ScanConfig) ([]domain.Asset, error) {
	// Placeholder for discovery logic
	assets := []domain.Asset{}
	for _, target := range config.Targets {
		asset := domain.NewAsset()
		asset.HostName = target
		asset.IPAddress = target
		assets = append(assets, *asset)
	}
	return assets, nil
}

func (o *Orchestrator) runVulnerabilityScans(ctx context.Context, config ScanConfig) ([]domain.Finding, error) {
	if !moduleEnabled(config.Modules, nuclei.AdapterName) {
		return []domain.Finding{}, nil
	}

	scanner, ok := o.registry.Get(nuclei.AdapterName)
	if !ok {
		return nil, fmt.Errorf("scanner %q is not registered", nuclei.AdapterName)
	}

	findings := make([]domain.Finding, 0)
	for _, target := range config.Targets {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("nuclei scan canceled: %w", err)
		}

		targetFindings, err := scanner.Scan(ctx, target, nil)
		if err != nil {
			return nil, fmt.Errorf("nuclei scan for %q failed: %w", target, err)
		}
		findings = append(findings, targetFindings...)
	}

	return findings, nil
}

func moduleEnabled(modules []string, name string) bool {
	for _, module := range modules {
		if strings.EqualFold(strings.TrimSpace(module), name) {
			return true
		}
	}
	return false
}

func (o *Orchestrator) correlateFindings(result *ScanResult) {
	// TODO: Implement finding correlation logic
	o.log.Debugf("Correlating %d findings", len(result.Findings))
}

func (o *Orchestrator) calculateRiskScore(result *ScanResult) int {
	if len(result.Findings) == 0 {
		return 0
	}

	score := 0
	for _, finding := range result.Findings {
		switch finding.Severity {
		case "critical":
			score += 40
		case "high":
			score += 25
		case "medium":
			score += 10
		case "low":
			score += 5
		case "info":
			score += 1
		}
	}

	// Cap score at 100
	if score > 100 {
		score = 100
	}

	return score
}
