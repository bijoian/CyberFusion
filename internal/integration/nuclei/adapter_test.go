package nuclei

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bijoian/cyberfusion/internal/database"
	"github.com/bijoian/cyberfusion/internal/domain"
	"github.com/sirupsen/logrus"
)

func TestParseNucleiJSONL(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "results.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	adapter := New(logrus.New())
	findings, err := adapter.ParseNucleiJSONL(string(fixture), "ignored.example.test")
	if err != nil {
		t.Fatalf("ParseNucleiJSONL() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("ParseNucleiJSONL() returned %d findings, want 2", len(findings))
	}

	finding := findings[0]
	if finding.TemplateID != "CVE-2024-12345" || finding.TemplatePath != "http/cves/2024/CVE-2024-12345.yaml" {
		t.Errorf("template metadata = (%q, %q)", finding.TemplateID, finding.TemplatePath)
	}
	if finding.Host != "https://app.example.test" || finding.MatchedAt != "https://app.example.test/vulnerable" || finding.Protocol != "https" {
		t.Errorf("target metadata was not preserved: %#v", finding)
	}
	if finding.Severity != "high" || finding.Remediation != "Upgrade Example Product to a fixed version." {
		t.Errorf("finding details not preserved: severity=%q remediation=%q", finding.Severity, finding.Remediation)
	}
	if !strings.Contains(finding.Evidence, "affected-version: 1.0") || finding.Sources[0] != AdapterName {
		t.Errorf("evidence or source attribution missing: %#v", finding)
	}
	if finding.Vulnerability == nil {
		t.Fatal("finding vulnerability was not created")
	}
	if got := finding.Vulnerability.CVEs; len(got) != 2 || got[0] != "CVE-2024-12345" {
		t.Errorf("CVEs = %#v", got)
	}
	if finding.Vulnerability.CWE != "CWE-79" || finding.Vulnerability.CVSS != 8.1 {
		t.Errorf("vulnerability classification not preserved: %#v", finding.Vulnerability)
	}
	if len(finding.References) != 1 || finding.Classification["cvss-metrics"] == "" {
		t.Errorf("references or classification not preserved: %#v", finding)
	}

	second := findings[1]
	if second.TemplatePath != "http/misconfiguration/missing-security-header.yaml" || second.Vulnerability.CWE != "CWE-693" {
		t.Errorf("fallback template path or scalar classification not parsed: %#v", second)
	}
}

func TestParseNucleiJSONLMalformedOutput(t *testing.T) {
	adapter := New(logrus.New())
	_, err := adapter.ParseNucleiJSONL(`{"template-id":"valid"}
not-json`, "example.test")
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("ParseNucleiJSONL() error = %v, want malformed line 2 error", err)
	}
}

func TestAuthorizedTarget(t *testing.T) {
	tests := []struct {
		target  string
		wantErr bool
	}{
		{target: "https://example.test"},
		{target: "  example.test  "},
		{target: "", wantErr: true},
		{target: "-tags cve", wantErr: true},
		{target: "example.test\n-other", wantErr: true},
		{target: "example.test other", wantErr: true},
		{target: "file:///sensitive-path", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			_, err := authorizedTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("authorizedTarget(%q) error = %v, wantErr %t", tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestCanceledError(t *testing.T) {
	if !strings.Contains(canceledError(context.DeadlineExceeded).Error(), "timed out") {
		t.Error("deadline error should identify timeout")
	}
	if !errors.Is(canceledError(context.Canceled), context.Canceled) {
		t.Error("cancellation should wrap context cancellation")
	}
}

func TestScanReportsMissingBinary(t *testing.T) {
	adapter := New(logrus.New())
	adapter.binary = "cyberfusion-nuclei-does-not-exist"

	_, err := adapter.Scan(context.Background(), "https://example.test", nil)
	if err == nil || !strings.Contains(err.Error(), "binary not found") {
		t.Fatalf("Scan() error = %v, want missing binary error", err)
	}
}

func TestFindingPersistence(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "results.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings, err := New(logrus.New()).ParseNucleiJSONL(string(fixture), "ignored.example.test")
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	db, err := database.New(t.TempDir(), logrus.New())
	if err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skip("SQLite persistence test requires a CGO-enabled Go toolchain")
		}
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	if err := db.GetDB().Create(&findings[0]).Error; err != nil {
		t.Fatalf("persist finding: %v", err)
	}
	var stored domain.Finding
	if err := db.GetDB().Preload("Vulnerability").First(&stored, "id = ?", findings[0].ID).Error; err != nil {
		t.Fatalf("load finding: %v", err)
	}
	if stored.TemplateID != findings[0].TemplateID || stored.Classification["cve-id"] != "CVE-2024-12345, CVE-2024-99999" {
		t.Errorf("structured finding fields were not persisted: %#v", stored)
	}
	if stored.Vulnerability == nil || stored.Vulnerability.CVE != "CVE-2024-12345" {
		t.Errorf("vulnerability was not persisted: %#v", stored.Vulnerability)
	}
}
