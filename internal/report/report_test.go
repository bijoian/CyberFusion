package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bijoian/cyberfusion/internal/domain"
)

func TestGenerateCreatesEscapedReports(t *testing.T) {
	input := reportFixture()
	outputDir := t.TempDir()

	artifacts, err := Generate(input, Options{
		OutputDir: outputDir,
		Formats:   []Format{FormatHTML, FormatJSON, FormatPDF},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(artifacts) != 3 {
		t.Fatalf("Generate() created %d artifacts, want 3", len(artifacts))
	}

	contents := make(map[Format]string, len(artifacts))
	for _, artifact := range artifacts {
		if filepath.Dir(artifact.Path) != outputDir {
			t.Errorf("artifact path %q is outside output directory %q", artifact.Path, outputDir)
		}
		content, err := os.ReadFile(artifact.Path)
		if err != nil {
			t.Fatalf("ReadFile(%q) error = %v", artifact.Path, err)
		}
		contents[artifact.Format] = string(content)
	}

	var document Document
	if err := json.Unmarshal([]byte(contents[FormatJSON]), &document); err != nil {
		t.Fatalf("JSON report is invalid: %v", err)
	}
	if document.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", document.SchemaVersion, SchemaVersion)
	}
	if document.Summary.SeverityCounts.Critical != 1 || document.Summary.SeverityCounts.High != 1 {
		t.Errorf("unexpected severity counts: %+v", document.Summary.SeverityCounts)
	}
	if got := document.Findings[0].CVEs; len(got) != 1 || got[0] != "CVE-2024-12345" {
		t.Errorf("finding CVEs = %v, want [CVE-2024-12345]", got)
	}
	if strings.Contains(contents[FormatHTML], "<script>alert(1)</script>") {
		t.Error("HTML report contains unescaped untrusted content")
	}
	if !strings.Contains(contents[FormatHTML], "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("HTML report did not render escaped finding content")
	}
	if !strings.HasPrefix(contents[FormatPDF], "%PDF-1.4") {
		t.Error("PDF report does not have a PDF header")
	}
	if !strings.Contains(contents[FormatPDF], "CyberFusion Security Assessment") {
		t.Error("PDF report does not contain report content")
	}
	if !strings.Contains(contents[FormatPDF], "\nxref\n") || !strings.HasSuffix(contents[FormatPDF], "%%EOF\n") {
		t.Error("PDF report does not contain a complete cross-reference table")
	}

	if _, err := Generate(input, Options{OutputDir: outputDir, Formats: []Format{FormatHTML}}); err == nil {
		t.Error("Generate() succeeded when the deterministic report path already exists")
	}
}

func TestGenerateHandlesScanWithoutDiscoveries(t *testing.T) {
	input := Input{Scan: &domain.Scan{ID: "empty-scan", Targets: []string{}}}

	document, err := BuildDocument(input)
	if err != nil {
		t.Fatalf("BuildDocument() error = %v", err)
	}
	if document.Summary.TotalAssets != 0 || document.Summary.TotalFindings != 0 {
		t.Errorf("unexpected empty scan summary: %+v", document.Summary)
	}

	outputDir := filepath.Join(t.TempDir(), "nested", "reports")
	artifacts, err := Generate(input, Options{OutputDir: outputDir, Formats: []Format{FormatJSON}})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("Generate() created %d artifacts, want 1", len(artifacts))
	}
	content, err := os.ReadFile(artifacts[0].Path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var exported Document
	if err := json.Unmarshal(content, &exported); err != nil {
		t.Fatalf("empty JSON report is invalid: %v", err)
	}
	for _, field := range []string{`"targets": []`, `"assets": []`, `"findings": []`} {
		if !strings.Contains(string(content), field) {
			t.Errorf("empty report JSON does not contain %s: %s", field, content)
		}
	}
}

func TestParseFormatsNormalizesAndDeduplicates(t *testing.T) {
	formats, err := ParseFormats([]string{" JSON ", "html", "json", "pdf"})
	if err != nil {
		t.Fatalf("ParseFormats() error = %v", err)
	}
	want := []Format{FormatJSON, FormatHTML, FormatPDF}
	if len(formats) != len(want) {
		t.Fatalf("ParseFormats() = %v, want %v", formats, want)
	}
	for index := range want {
		if formats[index] != want[index] {
			t.Errorf("ParseFormats()[%d] = %q, want %q", index, formats[index], want[index])
		}
	}
}

func reportFixture() Input {
	started := time.Date(2026, time.September, 2, 3, 4, 5, 0, time.UTC)
	completed := started.Add(2 * time.Minute)
	cvss := float32(9.8)
	return Input{
		Scan: &domain.Scan{
			ID:          "scan-20260902",
			Name:        "Production perimeter",
			Description: "External assessment",
			Targets:     []string{"app.example.test", "10.0.0.5"},
			Status:      "completed",
			StartedAt:   &started,
			CompletedAt: &completed,
			Duration:    120,
			RiskScore:   85,
			Metadata:    `{"profile":"external"}`,
		},
		Assets: []domain.Asset{
			{ID: "asset-b", HostName: "app.example.test", IPAddress: "10.0.0.5", OS: "Linux", IsActive: true},
			{ID: "asset-a", HostName: "db.example.test", IPAddress: "10.0.0.4", OS: "Linux", IsActive: true},
		},
		Findings: []domain.Finding{
			{
				ID:          "finding-high",
				AssetID:     "asset-b",
				FindingType: "misconfiguration",
				Title:       "Unsafe banner",
				Description: "<script>alert(1)</script>",
				Severity:    "high",
				Confidence:  90,
				Status:      "open",
				Evidence:    "Server: example",
				Sources:     []string{"nmap", "nmap"},
				Remediation: "Remove the banner.",
			},
			{
				ID:          "finding-critical",
				AssetID:     "asset-a",
				FindingType: "vulnerability",
				Title:       "Critical CVE-2024-12345",
				Description: "A critical issue is present.",
				Severity:    "critical",
				Confidence:  99,
				Status:      "open",
				Sources:     []string{"scanner"},
				Vulnerability: &domain.Vulnerability{
					CVE:        "CVE-2024-12345",
					CWE:        "CWE-79",
					CVSS:       cvss,
					CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
			},
		},
	}
}
