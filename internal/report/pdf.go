package report

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

type pdfLine struct {
	text string
	bold bool
}

func renderPDF(document Document) ([]byte, error) {
	lines := pdfLines(document)
	if len(lines) == 0 {
		lines = []pdfLine{{text: "CyberFusion Security Assessment", bold: true}}
	}

	const linesPerPage = 46
	pages := make([][]pdfLine, 0, (len(lines)+linesPerPage-1)/linesPerPage)
	for len(lines) > 0 {
		end := linesPerPage
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, lines[:end])
		lines = lines[end:]
	}

	var output bytes.Buffer
	output.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	objects := make([][]byte, 0, 3+len(pages)*2)
	objects = append(objects, []byte("<< /Type /Catalog /Pages 2 0 R >>"))

	var pageReferences strings.Builder
	for index := range pages {
		fmt.Fprintf(&pageReferences, "%d 0 R ", 5+index*2)
	}
	objects = append(objects, []byte("<< /Type /Pages /Kids ["+pageReferences.String()+"] /Count "+strconv.Itoa(len(pages))+" >>"))
	objects = append(objects, []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))
	objects = append(objects, []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"))

	for index, page := range pages {
		content := pdfPageContent(page, index+1, len(pages))
		pageObject := fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>", 6+index*2)
		objects = append(objects, []byte(pageObject))
		stream := append([]byte(fmt.Sprintf("<< /Length %d >>\nstream\n", len(content))), content...)
		stream = append(stream, []byte("\nendstream")...)
		objects = append(objects, stream)
	}

	offsets := make([]int, len(objects)+1)
	for index, object := range objects {
		offsets[index+1] = output.Len()
		fmt.Fprintf(&output, "%d 0 obj\n", index+1)
		output.Write(object)
		output.WriteString("\nendobj\n")
	}
	xrefOffset := output.Len()
	fmt.Fprintf(&output, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for index := 1; index < len(offsets); index++ {
		fmt.Fprintf(&output, "%010d 00000 n \n", offsets[index])
	}
	fmt.Fprintf(&output, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xrefOffset)
	return output.Bytes(), nil
}

func pdfLines(document Document) []pdfLine {
	lines := []pdfLine{
		{text: "CyberFusion Security Assessment", bold: true},
		{text: "Scan ID: " + document.Scan.ID},
		{text: "Status: " + document.Scan.Status + " | Completed: " + formatTimestamp(document.Scan.CompletedAt)},
		{},
		{text: "EXECUTIVE RISK SUMMARY", bold: true},
		{text: fmt.Sprintf("Risk score: %d/100 | Exposure: %s", document.Summary.RiskScore, document.Summary.ExposureLevel)},
		{text: fmt.Sprintf("Assets: %d | Vulnerable assets: %d | Findings: %d", document.Summary.TotalAssets, document.Summary.VulnerableAssets, document.Summary.TotalFindings)},
		{text: fmt.Sprintf("Severity counts - Critical: %d  High: %d  Medium: %d  Low: %d  Info: %d  Unknown: %d", document.Summary.SeverityCounts.Critical, document.Summary.SeverityCounts.High, document.Summary.SeverityCounts.Medium, document.Summary.SeverityCounts.Low, document.Summary.SeverityCounts.Info, document.Summary.SeverityCounts.Unknown)},
		{},
		{text: "SCOPE", bold: true},
		{text: "Targets: " + targetsText(document.Scan.Targets)},
		{text: "Name: " + document.Scan.Name},
		{text: "Description: " + document.Scan.Description},
		{text: "Started: " + formatTimestamp(document.Scan.StartedAt) + " | Duration: " + strconv.FormatInt(document.Scan.DurationSeconds, 10) + " seconds"},
	}
	if document.Scan.Metadata != "" {
		lines = append(lines, pdfLine{text: "Metadata: " + document.Scan.Metadata})
	}

	lines = append(lines, pdfLine{}, pdfLine{text: "ASSET INVENTORY", bold: true})
	if len(document.Assets) == 0 {
		lines = append(lines, pdfLine{text: "No assets were discovered."})
	}
	for _, asset := range document.Assets {
		lines = append(lines, pdfLine{text: fmt.Sprintf("%s | %s | %s %s | %s", asset.HostName, asset.IPAddress, asset.OS, asset.OSVersion, activeText(asset.IsActive))})
	}

	lines = append(lines, pdfLine{}, pdfLine{text: "FINDINGS", bold: true})
	if len(document.Findings) == 0 {
		lines = append(lines, pdfLine{text: "No findings were recorded for this scan."})
	}
	for _, finding := range document.Findings {
		lines = append(lines,
			pdfLine{text: strings.ToUpper(finding.Severity) + ": " + finding.Title, bold: true},
			pdfLine{text: "Asset: " + finding.AssetID + " | Type: " + finding.Type + " | Confidence: " + strconv.Itoa(finding.Confidence) + "%"},
		)
		if len(finding.CVEs) > 0 || finding.CWE != "" || finding.CVSS != nil {
			cvss := ""
			if finding.CVSS != nil {
				cvss = strconv.FormatFloat(float64(*finding.CVSS), 'f', -1, 32)
			}
			lines = append(lines, pdfLine{text: "CVE: " + cvesText(finding.CVEs) + " | CWE: " + finding.CWE + " | CVSS: " + cvss})
		}
		lines = appendTextLines(lines, "Description: "+finding.Description)
		if finding.Evidence != "" {
			lines = appendTextLines(lines, "Evidence: "+finding.Evidence)
		}
		if finding.Remediation != "" {
			lines = appendTextLines(lines, "Remediation: "+finding.Remediation)
		}
		lines = append(lines, pdfLine{text: "Sources: " + sourcesText(finding.Sources)}, pdfLine{})
	}
	return wrapPDFLines(lines, 94)
}

func appendTextLines(lines []pdfLine, text string) []pdfLine {
	for _, line := range strings.Split(text, "\n") {
		lines = append(lines, pdfLine{text: line})
	}
	return lines
}

func wrapPDFLines(lines []pdfLine, width int) []pdfLine {
	wrapped := make([]pdfLine, 0, len(lines))
	for _, line := range lines {
		if line.text == "" {
			wrapped = append(wrapped, line)
			continue
		}
		for _, paragraph := range strings.Split(line.text, "\n") {
			words := strings.Fields(paragraph)
			if len(words) == 0 {
				wrapped = append(wrapped, pdfLine{})
				continue
			}
			current := ""
			for _, word := range words {
				if len(current) > 0 && len(current)+1+len(word) > width {
					wrapped = append(wrapped, pdfLine{text: current, bold: line.bold})
					current = word
					continue
				}
				if current == "" {
					current = word
				} else {
					current += " " + word
				}
			}
			if current != "" {
				wrapped = append(wrapped, pdfLine{text: current, bold: line.bold})
			}
		}
	}
	return wrapped
}

func pdfPageContent(lines []pdfLine, page, totalPages int) []byte {
	var output strings.Builder
	for index, line := range lines {
		font := "/F1"
		size := 9
		if line.bold {
			font = "/F2"
			size = 10
		}
		y := 752 - index*15
		fmt.Fprintf(&output, "BT %s %d Tf 48 %d Td (%s) Tj ET\n", font, size, y, pdfEscape(line.text))
	}
	fmt.Fprintf(&output, "BT /F1 8 Tf 48 24 Td (CyberFusion report | Page %d of %d | %s) Tj ET\n", page, totalPages, pdfEscape(SchemaVersion))
	return []byte(output.String())
}

func pdfEscape(value string) string {
	var output strings.Builder
	for len(value) > 0 {
		runeValue, size := utf8.DecodeRuneInString(value)
		value = value[size:]
		switch runeValue {
		case '\\', '(', ')':
			output.WriteByte('\\')
			output.WriteRune(runeValue)
		case '\n', '\r', '\t':
			output.WriteByte(' ')
		default:
			if runeValue >= 32 && runeValue <= 255 {
				output.WriteByte(byte(runeValue))
			} else {
				output.WriteByte('?')
			}
		}
	}
	return output.String()
}

func activeText(active bool) string {
	if active {
		return "active"
	}
	return "inactive"
}
