// Package report creates portable scan reports from CyberFusion's canonical scan data.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/bijoian/cyberfusion/internal/domain"
)

const (
	// SchemaVersion identifies the stable JSON report schema.
	SchemaVersion = "cyberfusion.report/v1"
)

// Format identifies a supported report file format.
type Format string

const (
	FormatHTML Format = "html"
	FormatJSON Format = "json"
	FormatPDF  Format = "pdf"
)

// Input is the canonical scan data to export. The report generator never runs scanners
// or reads from external services.
type Input struct {
	Scan     *domain.Scan
	Assets   []domain.Asset
	Findings []domain.Finding
}

// Options controls where and how reports are written.
type Options struct {
	OutputDir string
	Formats   []Format
}

// Artifact describes a report file created by Generate.
type Artifact struct {
	Format Format
	Path   string
}

// Document is the stable JSON export schema. Arrays are always encoded, including when
// empty, to make the document straightforward for downstream consumers to process.
type Document struct {
	SchemaVersion string         `json:"schema_version"`
	Scan          ScanMetadata   `json:"scan"`
	Summary       RiskSummary    `json:"summary"`
	Assets        []Asset        `json:"assets"`
	Findings      []Finding      `json:"findings"`
}

// ScanMetadata records scan identity and scope.
type ScanMetadata struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Status          string    `json:"status"`
	Targets         []string  `json:"targets"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	DurationSeconds int64     `json:"duration_seconds"`
	RiskScore       int       `json:"risk_score"`
	Metadata        string    `json:"metadata,omitempty"`
}

// RiskSummary provides an executive view of exposure.
type RiskSummary struct {
	RiskScore        int            `json:"risk_score"`
	ExposureLevel    string         `json:"exposure_level"`
	TotalAssets      int            `json:"total_assets"`
	VulnerableAssets int            `json:"vulnerable_assets"`
	TotalFindings    int            `json:"total_findings"`
	SeverityCounts   SeverityCounts `json:"severity_counts"`
}

// SeverityCounts contains every recognized severity plus unrecognized values.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Unknown  int `json:"unknown"`
}

// Asset is an inventory entry in a report.
type Asset struct {
	ID         string    `json:"id"`
	HostName   string    `json:"hostname"`
	IPAddress  string    `json:"ip_address"`
	MACAddress string    `json:"mac_address"`
	OS         string    `json:"os"`
	OSVersion  string    `json:"os_version"`
	Location   Location  `json:"location"`
	IsActive   bool      `json:"is_active"`
	FirstSeen  time.Time `json:"first_seen,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
}

// Location is the geographic metadata associated with an asset.
type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Region    string  `json:"region"`
}

// Finding is a normalized finding entry. CVSS and CVSS vector are omitted when no
// vulnerability record supplied those values.
type Finding struct {
	ID          string   `json:"id"`
	AssetID     string   `json:"asset_id"`
	ServiceID   string   `json:"service_id"`
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Confidence  int      `json:"confidence"`
	Status      string   `json:"status"`
	CVEs        []string `json:"cves"`
	CWE         string   `json:"cwe"`
	CVSS        *float32 `json:"cvss,omitempty"`
	CVSSVector  string   `json:"cvss_vector,omitempty"`
	Evidence    string   `json:"evidence"`
	Sources     []string `json:"sources"`
	Remediation string   `json:"remediation"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

var cvePattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

// ParseFormats validates and normalizes CLI format values.
func ParseFormats(values []string) ([]Format, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one report format is required")
	}

	formats := make([]Format, 0, len(values))
	seen := make(map[Format]struct{}, len(values))
	for _, value := range values {
		format := Format(strings.ToLower(strings.TrimSpace(value)))
		switch format {
		case FormatHTML, FormatJSON, FormatPDF:
		default:
			return nil, fmt.Errorf("unsupported report format %q (supported: html, json, pdf)", value)
		}
		if _, exists := seen[format]; !exists {
			seen[format] = struct{}{}
			formats = append(formats, format)
		}
	}
	return formats, nil
}

// BuildDocument creates a deterministic representation of the supplied canonical data.
func BuildDocument(input Input) (Document, error) {
	if input.Scan == nil {
		return Document{}, fmt.Errorf("scan is required")
	}
	if strings.TrimSpace(input.Scan.ID) == "" {
		return Document{}, fmt.Errorf("scan ID is required")
	}

	assets := make([]Asset, 0, len(input.Assets))
	for _, source := range input.Assets {
		assets = append(assets, Asset{
			ID:         source.ID,
			HostName:   source.HostName,
			IPAddress:  source.IPAddress,
			MACAddress: source.MACAddress,
			OS:         source.OS,
			OSVersion:  source.OSVersion,
			Location: Location{
				Latitude:  source.Location.Latitude,
				Longitude: source.Location.Longitude,
				Country:   source.Location.Country,
				City:      source.Location.City,
				Region:    source.Location.Region,
			},
			IsActive:  source.IsActive,
			FirstSeen: source.FirstSeen.UTC(),
			LastSeen:  source.LastSeen.UTC(),
		})
	}
	sort.SliceStable(assets, func(i, j int) bool {
		return assetSortKey(assets[i]) < assetSortKey(assets[j])
	})

	findings := make([]Finding, 0, len(input.Findings))
	counts := SeverityCounts{}
	vulnerableAssets := make(map[string]struct{})
	for _, source := range input.Findings {
		finding := normalizeFinding(source)
		findings = append(findings, finding)
		incrementSeverity(&counts, finding.Severity)
		if finding.AssetID != "" {
			vulnerableAssets[finding.AssetID] = struct{}{}
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return findingSortKey(findings[i]) < findingSortKey(findings[j])
	})

	targets := make([]string, len(input.Scan.Targets))
	copy(targets, input.Scan.Targets)
	sort.Strings(targets)
	document := Document{
		SchemaVersion: SchemaVersion,
		Scan: ScanMetadata{
			ID:              input.Scan.ID,
			Name:            input.Scan.Name,
			Description:     input.Scan.Description,
			Status:          input.Scan.Status,
			Targets:         targets,
			StartedAt:       utcTimestamp(input.Scan.StartedAt),
			CompletedAt:     utcTimestamp(input.Scan.CompletedAt),
			DurationSeconds: input.Scan.Duration,
			RiskScore:       input.Scan.RiskScore,
			Metadata:        input.Scan.Metadata,
		},
		Summary: RiskSummary{
			RiskScore:        input.Scan.RiskScore,
			ExposureLevel:    exposureLevel(input.Scan.RiskScore, counts),
			TotalAssets:      len(assets),
			VulnerableAssets: len(vulnerableAssets),
			TotalFindings:    len(findings),
			SeverityCounts:   counts,
		},
		Assets:   assets,
		Findings: findings,
	}
	return document, nil
}

// Generate renders the requested formats and writes them with exclusive creation, so an
// existing deterministic filename is never overwritten.
func Generate(input Input, options Options) ([]Artifact, error) {
	document, err := BuildDocument(input)
	if err != nil {
		return nil, err
	}
	if len(options.Formats) == 0 {
		return nil, fmt.Errorf("at least one report format is required")
	}
	if strings.TrimSpace(options.OutputDir) == "" {
		return nil, fmt.Errorf("output directory is required")
	}
	if err := os.MkdirAll(options.OutputDir, 0750); err != nil {
		return nil, fmt.Errorf("create report directory %q: %w", options.OutputDir, err)
	}

	type pendingArtifact struct {
		artifact Artifact
		content  []byte
	}
	pending := make([]pendingArtifact, 0, len(options.Formats))
	seen := make(map[Format]struct{}, len(options.Formats))
	for _, format := range options.Formats {
		if _, exists := seen[format]; exists {
			continue
		}
		seen[format] = struct{}{}

		content, err := render(document, format)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(options.OutputDir, reportFileName(document.Scan.ID, format))
		if _, err := os.Stat(path); err == nil {
			return nil, fmt.Errorf("report already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect report path %q: %w", path, err)
		}
		pending = append(pending, pendingArtifact{
			artifact: Artifact{Format: format, Path: path},
			content:  content,
		})
	}

	created := make([]string, 0, len(pending))
	for _, item := range pending {
		if err := writeNewFile(item.artifact.Path, item.content); err != nil {
			for _, createdPath := range created {
				_ = os.Remove(createdPath)
			}
			return nil, err
		}
		created = append(created, item.artifact.Path)
	}

	artifacts := make([]Artifact, 0, len(pending))
	for _, item := range pending {
		artifacts = append(artifacts, item.artifact)
	}
	return artifacts, nil
}

func render(document Document, format Format) ([]byte, error) {
	switch format {
	case FormatHTML:
		return renderHTML(document)
	case FormatJSON:
		content, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("encode JSON report: %w", err)
		}
		return append(content, '\n'), nil
	case FormatPDF:
		return renderPDF(document)
	default:
		return nil, fmt.Errorf("unsupported report format %q", format)
	}
}

func normalizeFinding(source domain.Finding) Finding {
	cves := cvePattern.FindAllString(source.Title+"\n"+source.Description, -1)
	for index := range cves {
		cves[index] = strings.ToUpper(cves[index])
	}
	var cwe, vector string
	var cvss *float32
	if source.Vulnerability != nil {
		if source.Vulnerability.CVE != "" {
			cves = append(cves, strings.ToUpper(strings.TrimSpace(source.Vulnerability.CVE)))
		}
		cwe = source.Vulnerability.CWE
		vector = source.Vulnerability.CVSSVector
		value := source.Vulnerability.CVSS
		cvss = &value
	}
	cves = uniqueSorted(cves)

	return Finding{
		ID:          source.ID,
		AssetID:     source.AssetID,
		ServiceID:   source.ServiceID,
		Type:        source.FindingType,
		Title:       source.Title,
		Description: source.Description,
		Severity:    normalizedSeverity(source.Severity),
		Confidence:  source.Confidence,
		Status:      source.Status,
		CVEs:        cves,
		CWE:         cwe,
		CVSS:        cvss,
		CVSSVector:  vector,
		Evidence:    source.Evidence,
		Sources:     uniqueSorted(source.Sources),
		Remediation: source.Remediation,
		FirstSeen:   source.FirstSeen.UTC(),
		LastSeen:    source.LastSeen.UTC(),
	}
}

func writeNewFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return fmt.Errorf("create report %q: %w", path, err)
	}
	if _, err := file.Write(content); err != nil {
		closeErr := file.Close()
		_ = os.Remove(path)
		if closeErr != nil {
			return fmt.Errorf("write report %q: %w (close: %v)", path, err, closeErr)
		}
		return fmt.Errorf("write report %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close report %q: %w", path, err)
	}
	return nil
}

func reportFileName(scanID string, format Format) string {
	var name strings.Builder
	for _, character := range scanID {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-' || character == '_' {
			name.WriteRune(character)
		}
	}
	if name.Len() == 0 {
		name.WriteString("scan")
	}
	return "cyberfusion-" + name.String() + "." + string(format)
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; !exists {
			seen[trimmed] = struct{}{}
			result = append(result, trimmed)
		}
	}
	sort.Strings(result)
	return result
}

func assetSortKey(asset Asset) string {
	return strings.Join([]string{asset.IPAddress, asset.HostName, asset.ID}, "\x00")
}

func findingSortKey(finding Finding) string {
	return strings.Join([]string{severitySortKey(finding.Severity), finding.AssetID, finding.Title, finding.ID}, "\x00")
}

func severitySortKey(severity string) string {
	switch severity {
	case "critical":
		return "0"
	case "high":
		return "1"
	case "medium":
		return "2"
	case "low":
		return "3"
	case "info":
		return "4"
	default:
		return "5"
	}
}

func normalizedSeverity(severity string) string {
	value := strings.ToLower(strings.TrimSpace(severity))
	switch value {
	case "critical", "high", "medium", "low", "info":
		return value
	default:
		return "unknown"
	}
}

func incrementSeverity(counts *SeverityCounts, severity string) {
	switch severity {
	case "critical":
		counts.Critical++
	case "high":
		counts.High++
	case "medium":
		counts.Medium++
	case "low":
		counts.Low++
	case "info":
		counts.Info++
	default:
		counts.Unknown++
	}
}

func exposureLevel(riskScore int, counts SeverityCounts) string {
	if counts.Critical > 0 || riskScore >= 75 {
		return "critical"
	}
	if counts.High > 0 || riskScore >= 50 {
		return "high"
	}
	if counts.Medium > 0 || riskScore >= 25 {
		return "medium"
	}
	return "low"
}

func sourcesText(sources []string) string {
	return strings.Join(sources, ", ")
}

func targetsText(targets []string) string {
	return strings.Join(targets, ", ")
}

func cvesText(cves []string) string {
	return strings.Join(cves, ", ")
}

func formatTimestamp(timestamp *time.Time) string {
	if timestamp == nil {
		return "Not recorded"
	}
	return timestamp.UTC().Format(time.RFC3339)
}

func utcTimestamp(timestamp *time.Time) *time.Time {
	if timestamp == nil {
		return nil
	}
	normalized := timestamp.UTC()
	return &normalized
}
