package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleReport(t *testing.T) ([]Result, Meta) {
	t.Helper()
	root := hardenedRoot(t)
	write(t, root, "etc/ssh/sshd_config", "PermitRootLogin yes\nMaxAuthTries 9\n", 0o600)
	s := newSystem(root, goodCmds(), true)
	return RunAll(s), BuildMeta(s, "9.9.9")
}

func TestBuildMeta(t *testing.T) {
	m := BuildMeta(newSystem(hardenedRoot(t), nil, true), "1.2.3")
	if m.Hostname != "testbox" || m.OS != "Ubuntu 24.04 LTS" || !m.Root || m.Version != "1.2.3" {
		t.Errorf("meta = %+v", m)
	}
	if !strings.HasSuffix(m.Timestamp, " UTC") {
		t.Errorf("timestamp %q", m.Timestamp)
	}
}

func TestRenderTextPlain(t *testing.T) {
	results, meta := sampleReport(t)
	meta.Root = false
	out := RenderText(results, meta, false)
	for _, want := range []string{
		"bulwark 9.9.9 | testbox | Ubuntu 24.04 LTS",
		"(not root: some checks skipped)",
		"== SSH ==",
		"[FAIL] SSH-01   Root login over SSH is disabled",
		"           fix: Set 'PermitRootLogin no'",
		"Score: ",
		"passed,",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("color=false must not emit escape codes")
	}
}

func TestRenderTextOnlyShowsFixForFailAndWarn(t *testing.T) {
	out := RenderText([]Result{{ID: "A-01", Category: "A", Title: "t", Severity: Low,
		Status: Pass, Detail: "ok", Remediation: "should not show"}}, Meta{}, false)
	if strings.Contains(out, "fix:") {
		t.Errorf("unexpected fix line:\n%s", out)
	}
}

func TestRenderMarkdown(t *testing.T) {
	results, meta := sampleReport(t)
	md := RenderMarkdown(results, meta)
	if !strings.HasPrefix(md, "# Hardening Audit: testbox\n") {
		t.Errorf("header: %q", md[:40])
	}
	for _, want := range []string{"## Priority fixes", "## All results", "| FAIL | SSH-01: Root login", "(bulwark 9.9.9)"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Failures come before warnings in the priority table.
	if strings.Index(md, "| FAIL | SSH-01") > strings.Index(md, "| WARN | SSH-04") {
		t.Error("FAIL rows must precede WARN rows")
	}
}

func TestMarkdownEscapesPipes(t *testing.T) {
	md := RenderMarkdown([]Result{{ID: "A-01", Category: "A", Title: "t", Severity: Low,
		Status: Warn, Detail: "a|b", Remediation: "c|d"}}, Meta{})
	if strings.Contains(md, "a|b") || strings.Contains(md, "c|d") || !strings.Contains(md, "a/b") {
		t.Errorf("pipes not escaped:\n%s", md)
	}
}

func TestRenderJSON(t *testing.T) {
	results, meta := sampleReport(t)
	out, err := RenderJSON(results, meta)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Meta    map[string]any   `json:"meta"`
		Score   int              `json:"score"`
		Grade   string           `json:"grade"`
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatal(err)
	}
	if data.Meta["hostname"] != "testbox" || len(data.Results) != 27 || data.Grade == "" {
		t.Errorf("unexpected payload: %+v", data.Meta)
	}
	for _, k := range []string{"id", "category", "title", "severity", "status", "detail", "remediation"} {
		if _, ok := data.Results[0][k]; !ok {
			t.Errorf("result missing key %q", k)
		}
	}
	if _, ok := data.Meta["version"]; ok {
		t.Error("version must not be part of meta")
	}
}
