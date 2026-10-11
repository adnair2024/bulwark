package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/adnair2024/bulwark/internal/audit"
)

// fakeHost writes a small fake root with a mix of passing and failing checks.
func fakeHost(t *testing.T) *audit.System {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"etc/os-release":                     "ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
		"etc/hostname":                       "testbox\n",
		"etc/passwd":                         "root:x:0:0::/root:/bin/sh\ntoor:x:0:0::/root:/bin/sh\n",
		"etc/ssh/sshd_config":                "PermitRootLogin yes\nPasswordAuthentication no\n",
		"proc/sys/kernel/randomize_va_space": "2\n",
		"proc/sys/kernel/dmesg_restrict":     "0\n",
	}
	for rel, text := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &audit.System{Root: root}
}

func newModel(t *testing.T, sys *audit.System) Model {
	t.Helper()
	meta := audit.BuildMeta(sys, "test")
	return New(sys, meta, filepath.Join(t.TempDir(), "report.md"))
}

// finish feeds every check result to Update, as the runtime would.
func finish(t *testing.T, m Model) Model {
	t.Helper()
	for i := 0; !m.Done(); i++ {
		if i > len(m.checks) {
			t.Fatal("model never finished")
		}
		next, _ := m.Update(m.runCheck(len(m.results))())
		m = next.(Model)
	}
	return m
}

func resize(m Model, w, h int) Model {
	next, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return next.(Model)
}

func press(m Model, k string) Model {
	var msg tea.KeyMsg
	switch k {
	case "up":
		msg = tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		msg = tea.KeyMsg{Type: tea.KeyDown}
	case "ctrl+c":
		msg = tea.KeyMsg{Type: tea.KeyCtrlC}
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	}
	next, _ := m.Update(msg)
	return next.(Model)
}

func selectedID(m Model) string {
	return m.results[m.visible[m.cursor]].ID
}

func TestRunningStateShowsProgress(t *testing.T) {
	m := newModel(t, fakeHost(t))
	if m.Done() {
		t.Fatal("must start in the running state")
	}
	if v := m.View(); !strings.Contains(v, "Check 1 of 27") || !strings.Contains(v, "SSH-01") {
		t.Errorf("running view:\n%s", v)
	}
	next, cmd := m.Update(m.runCheck(0)())
	m = next.(Model)
	if len(m.results) != 1 || cmd == nil {
		t.Fatalf("one result and a follow-up command expected, got %d results, cmd nil=%v", len(m.results), cmd == nil)
	}
	if !strings.Contains(m.View(), "Check 2 of 27") {
		t.Errorf("progress did not advance:\n%s", m.View())
	}
}

func TestRunsEveryCheckOnePerCommand(t *testing.T) {
	m := finish(t, newModel(t, fakeHost(t)))
	if len(m.results) != 27 || len(m.visible) != 27 {
		t.Fatalf("results=%d visible=%d, want 27", len(m.results), len(m.visible))
	}
	if m.results[0].ID != "SSH-01" || m.results[26].ID != "LOG-02" {
		t.Errorf("order: first %s last %s", m.results[0].ID, m.results[26].ID)
	}
}

func TestResultsViewShowsHeaderScoreListAndDetail(t *testing.T) {
	m := resize(finish(t, newModel(t, fakeHost(t))), 120, 40)
	v := m.View()
	for _, want := range []string{
		"bulwark test", "testbox", "Ubuntu 24.04 LTS",
		"Not root", // fakeHost is not root
		"/100", "grade", "pass", "fail",
		"Checks", "filter: all", "SSH", "SSH-01",
		"PermitRootLogin is 'yes'", // detail of the selected check
		"Fix",
		"↑/k", "export markdown", "quit",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}
}

func TestViewsFitTheTerminal(t *testing.T) {
	for _, size := range [][2]int{{200, 50}, {120, 40}, {100, 30}, {99, 40}, {80, 30}, {60, 40}, {40, 24}} {
		m := resize(finish(t, newModel(t, fakeHost(t))), size[0], size[1])
		for i := 0; i < 5; i++ {
			m = press(m, "down")
		}
		lines := strings.Split(m.View(), "\n")
		if len(lines) > size[1] {
			t.Errorf("%dx%d: %d lines overflow the height", size[0], size[1], len(lines))
		}
		for i, l := range lines {
			if w := lipgloss.Width(l); w > size[0] {
				t.Errorf("%dx%d: line %d is %d wide: %q", size[0], size[1], i, w, l)
			}
		}
	}
}

func TestRunningViewFitsNarrowTerminal(t *testing.T) {
	m := resize(newModel(t, fakeHost(t)), 30, 10)
	for i, l := range strings.Split(m.View(), "\n") {
		if w := lipgloss.Width(l); w > 30 {
			t.Errorf("line %d is %d wide: %q", i, w, l)
		}
	}
}

func TestLayoutSwitchesAtBreakpoint(t *testing.T) {
	m := finish(t, newModel(t, fakeHost(t)))
	if !resize(m, 140, 40).wide() || resize(m, 80, 40).wide() {
		t.Error("expected side-by-side at 140 columns and stacked at 80")
	}
	// Side by side puts the list and the score panel on the same row.
	sideBySide := false
	for _, row := range strings.Split(resize(m, 140, 40).View(), "\n") {
		if strings.Contains(row, "/100") && strings.Contains(row, "SSH-") {
			sideBySide = true
		}
	}
	if !sideBySide {
		t.Error("wide layout should show the list and score on the same row")
	}
}

func TestCursorMovesAndClamps(t *testing.T) {
	m := resize(finish(t, newModel(t, fakeHost(t))), 120, 40)
	if selectedID(m) != "SSH-01" {
		t.Fatalf("starts on %s", selectedID(m))
	}
	m = press(press(m, "j"), "down")
	if selectedID(m) != "SSH-03" {
		t.Errorf("after two downs: %s", selectedID(m))
	}
	m = press(m, "k")
	if selectedID(m) != "SSH-02" {
		t.Errorf("after k: %s", selectedID(m))
	}
	for i := 0; i < 5; i++ {
		m = press(m, "up")
	}
	if m.cursor != 0 {
		t.Errorf("cursor must clamp at the top, got %d", m.cursor)
	}
	for i := 0; i < 100; i++ {
		m = press(m, "j")
	}
	if selectedID(m) != "LOG-02" {
		t.Errorf("cursor must clamp at the bottom, got %s", selectedID(m))
	}
}

func TestListScrollsToKeepSelectionVisible(t *testing.T) {
	m := resize(finish(t, newModel(t, fakeHost(t))), 80, 24)
	for i := 0; i < 26; i++ {
		m = press(m, "j")
		if !strings.Contains(m.listContent(m.width-4), selectedID(m)) {
			t.Fatalf("selected %s scrolled out of view:\n%s", selectedID(m), m.listContent(m.width-4))
		}
	}
	if m.offset == 0 {
		t.Error("list should have scrolled")
	}
	for i := 0; i < 26; i++ {
		m = press(m, "k")
	}
	if m.offset != 0 {
		t.Errorf("scrolling back up should return to the top, offset=%d", m.offset)
	}
}

func TestFilterCycles(t *testing.T) {
	m := resize(finish(t, newModel(t, fakeHost(t))), 120, 40)
	want := []string{"issues", "fail", "warn", "pass", "all"}
	for _, name := range want {
		m = press(m, "f")
		if m.filter.String() != name {
			t.Fatalf("filter = %s, want %s", m.filter, name)
		}
		for _, i := range m.visible {
			st := m.results[i].Status
			ok := map[string]bool{
				"issues": st == audit.Fail || st == audit.Warn,
				"fail":   st == audit.Fail,
				"warn":   st == audit.Warn,
				"pass":   st == audit.Pass,
				"all":    true,
			}[name]
			if !ok {
				t.Errorf("filter %s shows %s (%s)", name, m.results[i].ID, st)
			}
		}
	}
	if len(m.visible) != 27 {
		t.Errorf("all filter shows %d", len(m.visible))
	}
}

func TestFilterKeepsSelectionWhenItStillMatches(t *testing.T) {
	m := resize(finish(t, newModel(t, fakeHost(t))), 120, 40)
	for selectedID(m) != "KRN-06" { // a warning
		m = press(m, "j")
	}
	m = press(m, "f") // issues: still matches
	if selectedID(m) != "KRN-06" {
		t.Errorf("selection moved to %s", selectedID(m))
	}
	m = press(m, "f") // fail: no longer matches, so selection resets to the first row
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0", m.cursor)
	}
}

func TestEmptyFilterShowsMessage(t *testing.T) {
	m := resize(finish(t, newModel(t, &audit.System{Root: t.TempDir()})), 120, 40)
	for m.filter != filterFail {
		m = press(m, "f")
	}
	if len(m.visible) != 0 {
		t.Fatalf("expected no failures on an empty host, got %d", len(m.visible))
	}
	if v := m.View(); !strings.Contains(v, "No checks match this filter.") {
		t.Errorf("view:\n%s", v)
	}
	m = press(press(m, "j"), "k") // must not panic
}

func TestExportWritesMarkdown(t *testing.T) {
	m := finish(t, newModel(t, fakeHost(t)))
	m = press(m, "m")
	data, err := os.ReadFile(m.exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "# Hardening Audit: testbox") {
		t.Errorf("report: %.60s", data)
	}
	if !strings.Contains(m.View(), "Saved Markdown report to "+m.exportPath) {
		t.Errorf("status message missing:\n%s", m.View())
	}
	m = press(m, "j")
	if m.status != "" {
		t.Error("status should clear on the next action")
	}
}

func TestExportFailureIsReported(t *testing.T) {
	m := finish(t, newModel(t, fakeHost(t)))
	m.exportPath = filepath.Join(t.TempDir(), "missing-dir", "report.md")
	m = press(m, "m")
	if !strings.HasPrefix(m.status, "Export failed:") {
		t.Errorf("status = %q", m.status)
	}
}

func TestQuitKeys(t *testing.T) {
	for _, state := range []string{"running", "results"} {
		m := newModel(t, fakeHost(t))
		if state == "results" {
			m = finish(t, m)
		}
		for _, k := range []string{"q", "ctrl+c"} {
			var msg tea.KeyMsg
			if k == "q" {
				msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}
			} else {
				msg = tea.KeyMsg{Type: tea.KeyCtrlC}
			}
			_, cmd := m.Update(msg)
			if cmd == nil {
				t.Fatalf("%s/%s: no command", state, k)
			}
			if _, ok := cmd().(tea.QuitMsg); !ok {
				t.Errorf("%s/%s: not a quit command", state, k)
			}
		}
	}
}

func TestKeysAreIgnoredWhileRunning(t *testing.T) {
	m := newModel(t, fakeHost(t))
	m = press(press(m, "f"), "m")
	if m.filter != filterAll {
		t.Error("filter key must do nothing while running")
	}
	if _, err := os.Stat(m.exportPath); err == nil {
		t.Error("export must not happen while running")
	}
}

func TestSummary(t *testing.T) {
	m := newModel(t, fakeHost(t))
	next, _ := m.Update(m.runCheck(0)())
	if s := next.(Model).Summary(); !strings.Contains(s, "stopped after 1 of 27") {
		t.Errorf("partial summary: %q", s)
	}
	m = finish(t, m)
	if s := m.Summary(); !strings.HasPrefix(s, "bulwark: score ") || !strings.Contains(s, "grade") {
		t.Errorf("summary: %q", s)
	}
}

func TestRootNoticeHiddenWhenRoot(t *testing.T) {
	sys := fakeHost(t)
	sys.IsRoot = true
	m := resize(finish(t, newModel(t, sys)), 120, 40)
	if strings.Contains(m.View(), "Not root") {
		t.Error("root notice shown to root")
	}
}
