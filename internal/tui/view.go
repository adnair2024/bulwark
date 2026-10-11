package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/adnair2024/bulwark/internal/audit"
)

const (
	wideBreakpoint  = 100
	headerLines     = 2
	footerLines     = 2
	scorePanelH     = 5
	detailPanelH    = 11 // stacked layout only
	minListPanelH   = 6
	minDetailPanelH = 9
	listTitleLines  = 1
)

func (m Model) View() string {
	if !m.done {
		return m.runningView()
	}
	return lipgloss.NewStyle().MaxWidth(m.width).Render(m.resultsView())
}

func (m Model) runningView() string {
	done, total := len(m.results), len(m.checks)
	current := ""
	if done < total {
		current = m.checks[done].ID + " " + m.checks[done].Title
	}
	return strings.Join([]string{
		"",
		clip(m.width, fmt.Sprintf(" %s %s", m.spinner.View(), boldStyle.Render("Auditing "+m.meta.Hostname))),
		clip(m.width, " "+mutedStyle.Render(fmt.Sprintf("Check %d of %d: %s", min(done+1, total), total, current))),
		"",
		" " + m.progress.ViewAs(float64(done)/float64(total)),
		"",
		clip(m.width, " "+m.help.View(m.keys)),
	}, "\n")
}

// ---- layout ----

func (m Model) wide() bool { return m.width >= wideBreakpoint }

func (m Model) bodyHeight() int {
	return max(m.height-headerLines-footerLines, 8)
}

// listPanelSize is the outer size of the check list panel.
func (m Model) listPanelSize() (w, h int) {
	if m.wide() {
		return max(m.width*45/100, 44), m.bodyHeight()
	}
	return m.width, m.bodyHeight() - (scorePanelH - 1) - m.stackedDetailHeight()
}

// stackedDetailHeight shrinks the detail panel on short terminals so the
// list keeps at least minListPanelH lines.
func (m Model) stackedDetailHeight() int {
	return max(min(detailPanelH, m.bodyHeight()-(scorePanelH-1)-minListPanelH), 5)
}

// listRowCapacity is how many list lines fit inside the list panel.
func (m Model) listRowCapacity() int {
	_, h := m.listPanelSize()
	return max(h-2-listTitleLines, 1)
}

func (m Model) resultsView() string {
	body := m.stackedBody()
	if m.wide() {
		body = m.sideBySideBody()
	}
	return strings.Join([]string{m.headerView(), body, m.footerView()}, "\n")
}

func (m Model) sideBySideBody() string {
	lw, lh := m.listPanelSize()
	rw := m.width - lw
	sh := m.wideScoreHeight()
	score := panel(rw, sh, m.scoreWithLogo(rw-4))
	detail := panel(rw, lh-sh, m.detailContent(rw-4))
	return lipgloss.JoinHorizontal(lipgloss.Top,
		panel(lw, lh, m.listContent(lw-4)),
		lipgloss.JoinVertical(lipgloss.Left, score, detail))
}

func (m Model) stackedBody() string {
	_, lh := m.listPanelSize()
	return lipgloss.JoinVertical(lipgloss.Left,
		panel(m.width, scorePanelH-1, m.compactScoreContent(m.width-4)),
		panel(m.width, lh, m.listContent(m.width-4)),
		panel(m.width, m.stackedDetailHeight(), m.detailContent(m.width-4)))
}

// ---- header and footer ----

func (m Model) headerView() string {
	title := titleStyle.Render("bulwark "+m.meta.Version) + mutedStyle.Render(" | "+m.meta.Hostname+" | "+m.meta.OS)
	sub := mutedStyle.Render("Run " + m.meta.Timestamp)
	if !m.meta.Root {
		sub += "  " + noticeStyle.Render("Not root: some checks were skipped. Run with sudo for full coverage.")
	}
	return clip(m.width, title) + "\n" + clip(m.width, sub)
}

func (m Model) footerView() string {
	status := fmt.Sprintf("filter: %s (%d of %d)", m.filter, len(m.visible), len(m.results))
	if m.status != "" {
		status = m.status
	}
	return clip(m.width, mutedStyle.Render(status)) + "\n" + clip(m.width, m.help.View(m.keys))
}

// ---- score panel ----

// wideScoreHeight is the score panel height in the side-by-side layout; it
// grows to fit the distro logo when the terminal is tall enough.
func (m Model) wideScoreHeight() int {
	art := logoArt(m.meta.Distro)
	if h := len(art) + 2; m.bodyHeight()-h >= minDetailPanelH {
		return h
	}
	return scorePanelH
}

func (m Model) scoreWithLogo(w int) string {
	if m.wideScoreHeight() == scorePanelH {
		return m.scoreContent(w)
	}
	logo := renderLogo(m.meta.Distro)
	scoreW := w - lipgloss.Width(logo) - 3
	return lipgloss.JoinHorizontal(lipgloss.Center, logo, "   ", m.scoreContent(scoreW))
}

func (m Model) scoreContent(w int) string {
	pct, grade := audit.Score(m.results)
	gradeStyle := lipgloss.NewStyle().Bold(true).Foreground(gradeColor(grade))
	bar := m.progress
	bar.Width = max(min(w, 50), 10)
	return strings.Join([]string{
		clip(w, bigScoreStyle.Foreground(gradeColor(grade)).Render(fmt.Sprintf("%d", pct))+
			mutedStyle.Render("/100")+"   "+mutedStyle.Render("grade ")+gradeStyle.Render(grade)),
		bar.ViewAs(float64(pct) / 100),
		clip(w, m.countsLine()),
	}, "\n")
}

func (m Model) compactScoreContent(w int) string {
	pct, grade := audit.Score(m.results)
	head := bigScoreStyle.Foreground(gradeColor(grade)).Render(fmt.Sprintf("%d/100 grade %s", pct, grade))
	return clip(w, head) + "\n" + clip(w, m.countsLine())
}

func (m Model) countsLine() string {
	n := audit.Counts(m.results)
	parts := make([]string, 0, 5)
	for _, st := range []audit.Status{audit.Pass, audit.Fail, audit.Warn, audit.Skip, audit.Info} {
		parts = append(parts, statusStyle(st).Render(fmt.Sprintf("%d %s", n[st], strings.ToLower(string(st)))))
	}
	return strings.Join(parts, mutedStyle.Render(" · "))
}

// ---- check list ----

type listRow struct {
	header  bool
	visible int // index into m.visible for check rows
	text    string
}

func (m Model) listRows(w int) []listRow {
	var rows []listRow
	category := ""
	for vi, ri := range m.visible {
		r := m.results[ri]
		if r.Category != category {
			category = r.Category
			rows = append(rows, listRow{header: true, text: categoryStyle.Render(category)})
		}
		prefix := "  "
		title := r.Title
		if vi == m.cursor {
			prefix = "▸ "
			title = selectedStyle.Render(title)
		}
		rows = append(rows, listRow{visible: vi, text: clip(w,
			fmt.Sprintf("%s%s %-7s %s", prefix, statusStyle(r.Status).Render(string(r.Status)), r.ID, title))})
	}
	return rows
}

// cursorLine is the index in rows of the selected check.
func cursorLine(rows []listRow, cursor int) int {
	for i, r := range rows {
		if !r.header && r.visible == cursor {
			return i
		}
	}
	return 0
}

// clampScroll keeps the selected check (and its category heading) in view.
func (m *Model) clampScroll() {
	rows := m.listRows(m.width)
	line, capacity := cursorLine(rows, m.cursor), m.listRowCapacity()
	top := line
	if line > 0 && rows[line-1].header {
		top = line - 1
	}
	if top < m.offset {
		m.offset = top
	}
	if line >= m.offset+capacity {
		m.offset = line - capacity + 1
	}
	m.offset = max(0, min(m.offset, max(len(rows)-capacity, 0)))
}

func (m Model) listContent(w int) string {
	title := boldStyle.Render("Checks") + mutedStyle.Render(fmt.Sprintf("  filter: %s", m.filter))
	if len(m.visible) == 0 {
		return clip(w, title) + "\n" + mutedStyle.Render("No checks match this filter.")
	}
	rows := m.listRows(w)
	capacity := m.listRowCapacity()
	end := min(m.offset+capacity, len(rows))
	lines := []string{clip(w, title)}
	for _, r := range rows[m.offset:end] {
		lines = append(lines, r.text)
	}
	return strings.Join(lines, "\n")
}

// ---- detail pane ----

func (m Model) detailContent(w int) string {
	if m.cursor >= len(m.visible) {
		return mutedStyle.Render("Select a check to see its details.")
	}
	r := m.results[m.visible[m.cursor]]
	wrap := lipgloss.NewStyle().Width(max(w, 10))
	parts := []string{
		wrap.Render(boldStyle.Render(r.ID + "  " + r.Title)),
		statusStyle(r.Status).Render(string(r.Status)) + mutedStyle.Render(fmt.Sprintf("  %s severity", r.Severity)),
		"",
		wrap.Render(r.Detail),
	}
	if r.Remediation != "" && (r.Status == audit.Fail || r.Status == audit.Warn) {
		fix := boldStyle.Render("Fix") + "\n" + r.Remediation
		parts = append(parts, "", fixBoxStyle.Width(max(w-2, 8)).Render(fix))
	}
	return strings.Join(parts, "\n")
}
