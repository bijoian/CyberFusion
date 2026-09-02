// Package nuclei adapts structured Nuclei scan output to CyberFusion findings.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strconv"
	"strings"

	"github.com/bijoian/cyberfusion/internal/domain"
	"github.com/sirupsen/logrus"
)

const (
	AdapterName = "nuclei"
	Version     = "1.0.0"
)

// NucleiAdapter invokes the locally installed Nuclei binary.
type NucleiAdapter struct {
	log    *logrus.Logger
	binary string
}

// New creates a Nuclei adapter that uses nuclei from PATH.
func New(log *logrus.Logger) *NucleiAdapter {
	return &NucleiAdapter{log: log, binary: AdapterName}
}

func (n *NucleiAdapter) Name() string {
	return AdapterName
}

func (n *NucleiAdapter) Version() string {
	return Version
}

func (n *NucleiAdapter) SupportsProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "http", "https", "tcp", "udp", "dns", "ssl", "tls":
		return true
	default:
		return false
	}
}

// Scan runs Nuclei only for its explicitly supplied target. It does not accept
// scanner flags from options, preventing untrusted options from altering scope.
func (n *NucleiAdapter) Scan(ctx context.Context, target string, options map[string]interface{}) ([]domain.Finding, error) {
	_ = options

	target, err := authorizedTarget(target)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledError(err)
	}

	binary, err := exec.LookPath(n.binary)
	if err != nil {
		return nil, fmt.Errorf("nuclei binary not found in PATH: %w", err)
	}

	args := []string{"-u", target, "-jsonl", "-silent", "-no-color"}
	n.log.Debugf("Running nuclei against explicitly supplied target: %s", target)

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, canceledError(ctxErr)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			details := strings.TrimSpace(stderr.String())
			if details == "" {
				details = strings.TrimSpace(string(exitErr.Stderr))
			}
			if details == "" {
				details = "no diagnostic output"
			}
			return nil, fmt.Errorf("nuclei scan failed with exit code %d: %s", exitErr.ExitCode(), details)
		}
		return nil, fmt.Errorf("failed to execute nuclei: %w", err)
	}

	findings, err := n.ParseNucleiJSONL(string(output), target)
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func authorizedTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("nuclei target must be explicitly provided")
	}
	if strings.HasPrefix(target, "-") {
		return "", fmt.Errorf("invalid nuclei target %q: targets cannot begin with '-'", target)
	}
	if strings.ContainsAny(target, "\r\n\x00") {
		return "", fmt.Errorf("invalid nuclei target %q: contains control characters", target)
	}
	if strings.IndexFunc(target, func(r rune) bool { return r == ' ' || r == '\t' }) >= 0 {
		return "", fmt.Errorf("invalid nuclei target %q: contains whitespace", target)
	}
	if strings.Contains(target, "://") {
		parsed, err := url.ParseRequestURI(target)
		if err != nil || parsed.Host == "" {
			return "", fmt.Errorf("invalid nuclei target %q: invalid URL", target)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return "", fmt.Errorf("invalid nuclei target %q: only http and https URLs are supported", target)
		}
	}
	return target, nil
}

func canceledError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("nuclei scan timed out: %w", err)
	}
	return fmt.Errorf("nuclei scan canceled: %w", err)
}

// ParseNucleiJSONL parses Nuclei's JSONL output without treating diagnostics as
// findings. A non-JSON output line is reported explicitly rather than ignored.
func (n *NucleiAdapter) ParseNucleiJSONL(output, target string) ([]domain.Finding, error) {
	findings := make([]domain.Finding, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var result result
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return nil, fmt.Errorf("malformed nuclei JSONL output at line %d: %w", lineNumber, err)
		}
		finding, err := result.toFinding(target)
		if err != nil {
			return nil, fmt.Errorf("malformed nuclei JSONL output at line %d: %w", lineNumber, err)
		}
		findings = append(findings, finding)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read nuclei JSONL output: %w", err)
	}

	return findings, nil
}

type result struct {
	TemplateID   string      `json:"template-id"`
	TemplatePath string      `json:"template-path"`
	TemplateName string      `json:"template-name"`
	Template     string      `json:"template"`
	Info         info        `json:"info"`
	Type         string      `json:"type"`
	Host         string      `json:"host"`
	MatchedAt    string      `json:"matched-at"`
	Scheme       string      `json:"scheme"`
	IP           string      `json:"ip"`
	Port         string      `json:"port"`
	MatcherName  string      `json:"matcher-name"`
	MatcherType  string      `json:"matcher-type"`
	Extracted    stringsList `json:"extracted-results"`
}

type info struct {
	Name           string                     `json:"name"`
	Description    string                     `json:"description"`
	Severity       string                     `json:"severity"`
	Remediation    string                     `json:"remediation"`
	Reference      stringsList                `json:"reference"`
	Classification map[string]json.RawMessage `json:"classification"`
}

type stringsList []string

func (s *stringsList) UnmarshalJSON(data []byte) error {
	var value interface{}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	values, err := flattenStrings(value)
	if err != nil {
		return err
	}
	*s = values
	return nil
}

func flattenStrings(value interface{}) ([]string, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{typed}, nil
	case float64:
		return []string{strconv.FormatFloat(typed, 'f', -1, 64)}, nil
	case bool:
		return []string{strconv.FormatBool(typed)}, nil
	case []interface{}:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			itemValues, err := flattenStrings(item)
			if err != nil {
				return nil, err
			}
			values = append(values, itemValues...)
		}
		return values, nil
	default:
		return nil, fmt.Errorf("expected a string or array of strings, got %T", value)
	}
}

func (r result) toFinding(target string) (domain.Finding, error) {
	if strings.TrimSpace(r.TemplateID) == "" {
		return domain.Finding{}, fmt.Errorf("missing template-id")
	}

	host := firstNonEmpty(r.Host, target)
	matchedAt := firstNonEmpty(r.MatchedAt, host)
	protocol := firstNonEmpty(r.Scheme, r.Type)
	templatePath := firstNonEmpty(r.TemplatePath, r.Template)
	classification, err := normalizeClassification(r.Info.Classification)
	if err != nil {
		return domain.Finding{}, fmt.Errorf("invalid classification: %w", err)
	}

	templateName := firstNonEmpty(r.Info.Name, r.TemplateName)
	title := firstNonEmpty(templateName, r.TemplateID)
	description := firstNonEmpty(r.Info.Description, title)
	vulnerability := domain.NewVulnerability()
	vulnerability.Title = title
	vulnerability.Description = description
	vulnerability.Severity = normalizeSeverity(r.Info.Severity)
	vulnerability.CVEs = classificationValues(classification, "cve-id")
	vulnerability.CWEs = classificationValues(classification, "cwe-id")
	if len(vulnerability.CVEs) > 0 {
		vulnerability.CVE = vulnerability.CVEs[0]
	}
	if len(vulnerability.CWEs) > 0 {
		vulnerability.CWE = vulnerability.CWEs[0]
	}
	vulnerability.CVSS = cvssScore(classification["cvss-score"])
	vulnerability.CVSSVector = firstNonEmpty(classification["cvss-metrics"], classification["cvss-vector"])

	finding := domain.NewFinding()
	finding.AssetID = host
	finding.VulnerabilityID = vulnerability.ID
	finding.Vulnerability = vulnerability
	finding.FindingType = "vulnerability"
	finding.TemplateID = r.TemplateID
	finding.TemplatePath = templatePath
	finding.TemplateName = templateName
	finding.Host = host
	finding.MatchedAt = matchedAt
	finding.Protocol = protocol
	finding.Title = title
	finding.Description = description
	finding.Severity = vulnerability.Severity
	finding.Confidence = 90
	finding.Evidence = buildEvidence(matchedAt, host, protocol, r.MatcherName, r.MatcherType, r.Extracted)
	finding.Remediation = r.Info.Remediation
	finding.Sources = []string{AdapterName}
	finding.References = deduplicate(r.Info.Reference)
	finding.Classification = classification
	return *finding, nil
}

func normalizeClassification(values map[string]json.RawMessage) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	normalized := make(map[string]string, len(values))
	for key, raw := range values {
		var value interface{}
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		items, err := flattenStrings(value)
		if err != nil {
			encoded, marshalErr := json.Marshal(value)
			if marshalErr != nil {
				return nil, marshalErr
			}
			normalized[key] = string(encoded)
			continue
		}
		normalized[key] = strings.Join(deduplicate(items), ", ")
	}
	return normalized, nil
}

func classificationValues(classification map[string]string, key string) []string {
	value := strings.TrimSpace(classification[key])
	if value == "" {
		return nil
	}
	return deduplicate(strings.Split(value, ","))
}

func cvssScore(value string) float32 {
	score, err := strconv.ParseFloat(strings.TrimSpace(value), 32)
	if err != nil {
		return 0
	}
	return float32(score)
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(severity))
	default:
		return "info"
	}
}

func buildEvidence(matchedAt, host, protocol, matcherName, matcherType string, extracted []string) string {
	parts := []string{
		"Matched at: " + matchedAt,
		"Host: " + host,
	}
	if protocol != "" {
		parts = append(parts, "Protocol: "+protocol)
	}
	if matcherName != "" {
		matcher := matcherName
		if matcherType != "" {
			matcher += " (" + matcherType + ")"
		}
		parts = append(parts, "Matcher: "+matcher)
	}
	if len(extracted) > 0 {
		parts = append(parts, "Extracted results: "+strings.Join(deduplicate(extracted), " | "))
	}
	return strings.Join(parts, "\n")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func deduplicate(values []string) []string {
	unique := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}
