package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Meta describes the audited host and run.
type Meta struct {
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Timestamp string `json:"timestamp"`
	Root      bool   `json:"root"`
	Version   string `json:"-"`
	// Distro lists os-release ID followed by ID_LIKE, most specific first.
	Distro []string `json:"-"`
}

// BuildMeta collects host details for the report header.
func BuildMeta(s *System, version string) Meta {
	host, _ := s.Read("/etc/hostname")
	host = strings.TrimSpace(host)
	if host == "" {
		host, _ = os.Hostname()
	}
	osName := s.OSRelease()["PRETTY_NAME"]
	if osName == "" {
		osName = "Unknown Linux"
	}
	rel := s.OSRelease()
	distro := append([]string{rel["ID"]}, strings.Fields(rel["ID_LIKE"])...)
	return Meta{
		Distro:    distro,
		Hostname:  host,
		OS:        osName,
		Timestamp: time.Now().UTC().Format("2006-01-02 15:04 UTC"),
		Root:      s.IsRoot,
		Version:   version,
	}
}

// StatusColor is the color for a status, readable on light and dark terminals.
func StatusColor(st Status) lipgloss.AdaptiveColor {
	switch st {
	case Pass:
		return lipgloss.AdaptiveColor{Light: "28", Dark: "42"}
	case Fail:
		return lipgloss.AdaptiveColor{Light: "160", Dark: "203"}
	case Warn:
		return lipgloss.AdaptiveColor{Light: "130", Dark: "220"}
	case Info:
		return lipgloss.AdaptiveColor{Light: "30", Dark: "51"}
	}
	return lipgloss.AdaptiveColor{Light: "243", Dark: "245"} // SKIP
}

// RenderText is the static report for the terminal. With color false the
// output has no escape codes.
func RenderText(results []Result, meta Meta, color bool) string {
	bold := lipgloss.NewStyle()
	paint := func(st Status) string { return string(st) }
	if color {
		bold = bold.Bold(true)
		paint = func(st Status) string {
			return lipgloss.NewStyle().Foreground(StatusColor(st)).Render(string(st))
		}
	}

	pct, grade := Score(results)
	n := Counts(results)
	lines := []string{
		bold.Render(fmt.Sprintf("bulwark %s | %s | %s", meta.Version, meta.Hostname, meta.OS)),
		"Run " + meta.Timestamp,
		"",
	}
	if !meta.Root {
		lines[1] += "  (not root: some checks skipped)"
	}
	category := ""
	for _, r := range results {
		if r.Category != category {
			category = r.Category
			lines = append(lines, bold.Render(fmt.Sprintf("== %s ==", category)))
		}
		lines = append(lines,
			fmt.Sprintf("  [%s] %-8s %s", paint(r.Status), r.ID, r.Title),
			"           "+r.Detail)
		if (r.Status == Fail || r.Status == Warn) && r.Remediation != "" {
			lines = append(lines, "           fix: "+r.Remediation)
		}
	}
	lines = append(lines, "",
		bold.Render(fmt.Sprintf("Score: %d/100 (grade %s)", pct, grade)),
		summaryLine(n))
	return strings.Join(lines, "\n")
}

func summaryLine(n map[Status]int) string {
	return fmt.Sprintf("%d passed, %d failed, %d warnings, %d skipped, %d info",
		n[Pass], n[Fail], n[Warn], n[Skip], n[Info])
}

// RenderMarkdown is a shareable report with fixes listed by priority.
func RenderMarkdown(results []Result, meta Meta) string {
	pct, grade := Score(results)
	root := "yes"
	if !meta.Root {
		root = "no (some checks skipped)"
	}
	out := []string{
		"# Hardening Audit: " + meta.Hostname, "",
		"- **OS:** " + meta.OS,
		fmt.Sprintf("- **Run:** %s (bulwark %s)", meta.Timestamp, meta.Version),
		"- **Ran as root:** " + root,
		fmt.Sprintf("- **Score:** %d/100 (grade %s)", pct, grade),
		"- **Results:** " + summaryLine(Counts(results)), "",
	}
	var fixes []Result
	for _, r := range results {
		if r.Status == Fail || r.Status == Warn {
			fixes = append(fixes, r)
		}
	}
	if len(fixes) > 0 {
		rank := func(r Result) int {
			if r.Status == Fail {
				return 0
			}
			return 1
		}
		sort.SliceStable(fixes, func(i, j int) bool {
			if rank(fixes[i]) != rank(fixes[j]) {
				return rank(fixes[i]) < rank(fixes[j])
			}
			return fixes[i].Severity.Weight() > fixes[j].Severity.Weight()
		})
		out = append(out, "## Priority fixes", "",
			"| Status | Check | Severity | Fix |", "|---|---|---|---|")
		for _, r := range fixes {
			out = append(out, fmt.Sprintf("| %s | %s: %s | %s | %s |",
				r.Status, r.ID, r.Title, r.Severity, cell(r.Remediation)))
		}
		out = append(out, "")
	}
	out = append(out, "## All results", "",
		"| Status | ID | Category | Check | Detail |", "|---|---|---|---|---|")
	for _, r := range results {
		out = append(out, fmt.Sprintf("| %s | %s | %s | %s | %s |",
			r.Status, r.ID, r.Category, r.Title, cell(r.Detail)))
	}
	return strings.Join(out, "\n") + "\n"
}

// cell makes text safe for a Markdown table cell.
func cell(s string) string {
	return strings.ReplaceAll(s, "|", "/")
}

// RenderJSON is the machine-readable report.
func RenderJSON(results []Result, meta Meta) (string, error) {
	pct, grade := Score(results)
	b, err := json.MarshalIndent(struct {
		Meta    Meta     `json:"meta"`
		Score   int      `json:"score"`
		Grade   string   `json:"grade"`
		Results []Result `json:"results"`
	}{meta, pct, grade, results}, "", "  ")
	return string(b), err
}

// Summary is a one-line result for printing after the TUI exits.
func Summary(results []Result) string {
	pct, grade := Score(results)
	return fmt.Sprintf("bulwark: score %d/100 (grade %s) - %s", pct, grade, summaryLine(Counts(results)))
}
