// Package tui is the Bubble Tea front end for the audit engine.
package tui

import (
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/adnair2024/bulwark/internal/audit"
)

type filter int

const (
	filterAll filter = iota
	filterIssues
	filterFail
	filterWarn
	filterPass
	numFilters
)

func (f filter) String() string {
	return [...]string{"all", "issues", "fail", "warn", "pass"}[f]
}

func (f filter) matches(st audit.Status) bool {
	switch f {
	case filterIssues:
		return st == audit.Fail || st == audit.Warn
	case filterFail:
		return st == audit.Fail
	case filterWarn:
		return st == audit.Warn
	case filterPass:
		return st == audit.Pass
	}
	return true
}

// checkDoneMsg reports one finished check.
type checkDoneMsg struct{ result audit.Result }

// Model is the Bubble Tea model. It runs one check per command so the
// progress bar advances as each finishes, then shows the results browser.
type Model struct {
	sys    *audit.System
	meta   audit.Meta
	checks []audit.Check

	results []audit.Result
	done    bool

	spinner  spinner.Model
	progress progress.Model
	help     help.Model
	keys     keyMap

	filter  filter
	visible []int // indexes into results that pass the filter
	cursor  int   // index into visible
	offset  int   // first visible line of the check list

	width, height int
	exportPath    string
	status        string
}

// New builds a model that audits sys. The Markdown export key writes to
// exportPath.
func New(sys *audit.System, meta audit.Meta, exportPath string) Model {
	sys.ResetCache()
	sp := spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(titleStyle))
	return Model{
		sys:        sys,
		meta:       meta,
		checks:     audit.AllChecks(),
		spinner:    sp,
		progress:   progress.New(progress.WithSolidFill("63"), progress.WithoutPercentage()),
		help:       help.New(),
		keys:       newKeyMap(),
		width:      80,
		height:     24,
		exportPath: exportPath,
	}
}

// Done reports whether every check has finished.
func (m Model) Done() bool { return m.done }

// Results returns the results gathered so far.
func (m Model) Results() []audit.Result { return m.results }

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.runCheck(0))
}

func (m Model) runCheck(i int) tea.Cmd {
	sys, c := m.sys, m.checks[i]
	return func() tea.Msg { return checkDoneMsg{audit.RunCheck(sys, c)} }
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.progress.Width = max(min(m.width-8, 60), 10)
		m.help.Width = m.width
		m.clampScroll()
		return m, nil

	case spinner.TickMsg:
		if m.done {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case checkDoneMsg:
		m.results = append(m.results, msg.result)
		if len(m.results) < len(m.checks) {
			return m, m.runCheck(len(m.results))
		}
		m.done = true
		m.applyFilter()
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.Matches(msg, m.keys.Quit) {
		return m, tea.Quit
	}
	if !m.done {
		return m, nil
	}
	switch {
	case key.Matches(msg, m.keys.Up):
		m.moveCursor(-1)
	case key.Matches(msg, m.keys.Down):
		m.moveCursor(1)
	case key.Matches(msg, m.keys.Filter):
		m.filter = (m.filter + 1) % numFilters
		m.applyFilter()
	case key.Matches(msg, m.keys.Export):
		m.export()
	}
	return m, nil
}

func (m *Model) moveCursor(delta int) {
	if len(m.visible) == 0 {
		return
	}
	m.cursor = max(0, min(m.cursor+delta, len(m.visible)-1))
	m.status = ""
	m.clampScroll()
}

// applyFilter rebuilds the visible list, keeping the selected check when it
// still matches.
func (m *Model) applyFilter() {
	selected := -1
	if m.cursor < len(m.visible) {
		selected = m.visible[m.cursor]
	}
	m.visible = m.visible[:0]
	m.cursor = 0
	for i, r := range m.results {
		if m.filter.matches(r.Status) {
			if i == selected {
				m.cursor = len(m.visible)
			}
			m.visible = append(m.visible, i)
		}
	}
	m.status = ""
	m.offset = 0
	m.clampScroll()
}

func (m *Model) export() {
	md := audit.RenderMarkdown(m.results, m.meta)
	if err := os.WriteFile(m.exportPath, []byte(md), 0o644); err != nil {
		m.status = "Export failed: " + err.Error()
		return
	}
	m.status = "Saved Markdown report to " + m.exportPath
}

// Summary is the line printed after the TUI exits.
func (m Model) Summary() string {
	if !m.done {
		return fmt.Sprintf("bulwark: stopped after %d of %d checks", len(m.results), len(m.checks))
	}
	return audit.Summary(m.results)
}
