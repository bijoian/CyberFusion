package report

import (
	"bytes"
	"fmt"
	"html/template"
)

var htmlReportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"cves":      cvesText,
	"formatTime": formatTimestamp,
	"sources":   sourcesText,
	"targets":   targetsText,
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberFusion Security Report - {{.Scan.ID}}</title>
<style>
body{margin:0;background:#f4f7fb;color:#172033;font:14px/1.5 Arial,sans-serif}.page{max-width:1200px;margin:0 auto;padding:32px}.hero{background:#102a43;color:#fff;border-radius:12px;padding:28px}.hero h1{margin:0 0 6px;font-size:28px}.muted{color:#627d98}.hero .muted{color:#d9e2ec}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px;margin:22px 0}.card,section{background:#fff;border:1px solid #d9e2ec;border-radius:10px;padding:18px}.metric{font-size:28px;font-weight:bold;color:#102a43}.label{font-size:12px;font-weight:bold;text-transform:uppercase;letter-spacing:.04em;color:#627d98}h2{margin-top:0;color:#102a43}table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;vertical-align:top;border-bottom:1px solid #e6edf5}th{background:#f0f4f8;color:#334e68}.severity{font-weight:bold;text-transform:uppercase}.critical{color:#a61b1b}.high{color:#c05621}.medium{color:#b7791f}.low{color:#2b6cb0}.info{color:#2f855a}.unknown{color:#627d98}.finding{border-left:5px solid #627d98;margin:14px 0}.finding.critical{border-color:#a61b1b}.finding.high{border-color:#c05621}.finding.medium{border-color:#b7791f}.finding.low{border-color:#2b6cb0}.finding.info{border-color:#2f855a}.pre{white-space:pre-wrap;word-break:break-word}.meta{display:grid;grid-template-columns:180px 1fr;gap:8px;margin:0}.meta dt{font-weight:bold;color:#486581}.meta dd{margin:0}@media print{body{background:#fff}.page{max-width:none;padding:0}.card,section{break-inside:avoid;box-shadow:none}}
</style>
</head>
<body>
<main class="page">
<header class="hero"><h1>CyberFusion Security Assessment</h1><div>Scan {{.Scan.ID}}</div><div class="muted">Status: {{.Scan.Status}} | Completed: {{formatTime .Scan.CompletedAt}}</div></header>
<section><h2>Scan Scope</h2><dl class="meta"><dt>Targets</dt><dd>{{targets .Scan.Targets}}</dd><dt>Name</dt><dd>{{.Scan.Name}}</dd><dt>Description</dt><dd>{{.Scan.Description}}</dd><dt>Started</dt><dd>{{formatTime .Scan.StartedAt}}</dd><dt>Duration</dt><dd>{{.Scan.DurationSeconds}} seconds</dd>{{if .Scan.Metadata}}<dt>Metadata</dt><dd class="pre">{{.Scan.Metadata}}</dd>{{end}}</dl></section>
<section><h2>Executive Risk Summary</h2><div class="grid"><div class="card"><div class="label">Risk score</div><div class="metric">{{.Summary.RiskScore}}/100</div></div><div class="card"><div class="label">Exposure</div><div class="metric">{{.Summary.ExposureLevel}}</div></div><div class="card"><div class="label">Assets</div><div class="metric">{{.Summary.TotalAssets}}</div></div><div class="card"><div class="label">Findings</div><div class="metric">{{.Summary.TotalFindings}}</div></div><div class="card"><div class="label">Vulnerable assets</div><div class="metric">{{.Summary.VulnerableAssets}}</div></div></div><table><thead><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Unknown</th></tr></thead><tbody><tr><td>{{.Summary.SeverityCounts.Critical}}</td><td>{{.Summary.SeverityCounts.High}}</td><td>{{.Summary.SeverityCounts.Medium}}</td><td>{{.Summary.SeverityCounts.Low}}</td><td>{{.Summary.SeverityCounts.Info}}</td><td>{{.Summary.SeverityCounts.Unknown}}</td></tr></tbody></table></section>
<section><h2>Asset Inventory</h2>{{if .Assets}}<table><thead><tr><th>Host</th><th>IP address</th><th>Operating system</th><th>MAC address</th><th>Status</th></tr></thead><tbody>{{range .Assets}}<tr><td>{{.HostName}}</td><td>{{.IPAddress}}</td><td>{{.OS}} {{.OSVersion}}</td><td>{{.MACAddress}}</td><td>{{if .IsActive}}Active{{else}}Inactive{{end}}</td></tr>{{end}}</tbody></table>{{else}}<p class="muted">No assets were discovered.</p>{{end}}</section>
<section><h2>Findings</h2>{{if .Findings}}{{range .Findings}}<article class="card finding {{.Severity}}"><div class="severity {{.Severity}}">{{.Severity}}</div><h3>{{.Title}}</h3><dl class="meta"><dt>Asset</dt><dd>{{.AssetID}}</dd><dt>Type</dt><dd>{{.Type}}</dd><dt>Confidence</dt><dd>{{.Confidence}}%</dd><dt>Status</dt><dd>{{.Status}}</dd>{{if .CVEs}}<dt>CVE</dt><dd>{{cves .CVEs}}</dd>{{end}}{{if .CWE}}<dt>CWE</dt><dd>{{.CWE}}</dd>{{end}}{{if .CVSS}}<dt>CVSS</dt><dd>{{.CVSS}} {{.CVSSVector}}</dd>{{end}}<dt>Sources</dt><dd>{{sources .Sources}}</dd></dl><h4>Description</h4><div class="pre">{{.Description}}</div>{{if .Evidence}}<h4>Evidence</h4><div class="pre">{{.Evidence}}</div>{{end}}{{if .Remediation}}<h4>Remediation</h4><div class="pre">{{.Remediation}}</div>{{end}}</article>{{end}}{{else}}<p class="muted">No findings were recorded for this scan.</p>{{end}}</section>
<p class="muted">Schema: {{.SchemaVersion}}</p>
</main>
</body>
</html>`))

func renderHTML(document Document) ([]byte, error) {
	var output bytes.Buffer
	if err := htmlReportTemplate.Execute(&output, document); err != nil {
		return nil, fmt.Errorf("render HTML report: %w", err)
	}
	return output.Bytes(), nil
}
