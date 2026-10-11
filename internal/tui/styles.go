package tui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/adnair2024/bulwark/internal/audit"
)

// All TUI styling lives here. Colors are adaptive so they read on light and
// dark terminals; NO_COLOR and --no-color strip them via the color profile.
var (
	colorAccent = lipgloss.AdaptiveColor{Light: "25", Dark: "75"}
	colorMuted  = lipgloss.AdaptiveColor{Light: "243", Dark: "245"}

	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	mutedStyle    = lipgloss.NewStyle().Foreground(colorMuted)
	boldStyle     = lipgloss.NewStyle().Bold(true)
	categoryStyle = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
	selectedStyle = lipgloss.NewStyle().Bold(true)
	noticeStyle   = lipgloss.NewStyle().Foreground(audit.StatusColor(audit.Warn))

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorMuted).
			Padding(0, 1)

	fixBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(audit.StatusColor(audit.Pass)).
			Padding(0, 1)

	bigScoreStyle = lipgloss.NewStyle().Bold(true)
)

// logoColors are the brand colors for the distro logos.
var logoColors = map[string]lipgloss.AdaptiveColor{
	"arch":   {Light: "25", Dark: "39"},
	"ubuntu": {Light: "166", Dark: "208"},
	"debian": {Light: "160", Dark: "204"},
	"fedora": {Light: "26", Dark: "33"},
	"tux":    {Light: "240", Dark: "250"},
}

func statusStyle(st audit.Status) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(audit.StatusColor(st))
}

// gradeColor maps a letter grade to a status color: green for A/B, yellow
// for C/D, red for F.
func gradeColor(grade string) lipgloss.AdaptiveColor {
	switch grade {
	case "A", "B":
		return audit.StatusColor(audit.Pass)
	case "C", "D":
		return audit.StatusColor(audit.Warn)
	}
	return audit.StatusColor(audit.Fail)
}

// panel draws content in a bordered box of exactly w x h cells.
func panel(w, h int, content string) string {
	return panelStyle.
		Width(max(w-2, 1)).Height(max(h-2, 1)).
		MaxWidth(w).MaxHeight(h).
		Render(content)
}

// clip truncates a (possibly styled) line to w cells.
func clip(w int, s string) string {
	return lipgloss.NewStyle().MaxWidth(max(w, 1)).Render(s)
}
