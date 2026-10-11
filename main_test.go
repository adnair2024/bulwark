package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for rel, text := range map[string]string{
		"etc/os-release":                     "ID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
		"etc/hostname":                       "testbox\n",
		"etc/ssh/sshd_config":                "PermitRootLogin no\nPasswordAuthentication no\n",
		"etc/passwd":                         "root:x:0:0::/root:/bin/sh\n",
		"proc/sys/kernel/randomize_va_space": "2\n",
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLIOutputs(t *testing.T) {
	root, dir := fakeRoot(t), t.TempDir()
	outJSON, outMD := filepath.Join(dir, "out.json"), filepath.Join(dir, "out.md")
	code, stdout, _ := runCLI(t, "--root", root, "--json", outJSON, "--markdown", outMD, "--no-color")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	raw, err := os.ReadFile(outJSON)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Meta    struct{ Hostname string } `json:"meta"`
		Results []struct{ ID string }     `json:"results"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range data.Results {
		ids[r.ID] = true
	}
	if data.Meta.Hostname != "testbox" || !ids["SSH-01"] || !ids["NET-01"] || !ids["UPD-01"] {
		t.Errorf("unexpected JSON: %s", raw)
	}
	md, err := os.ReadFile(outMD)
	if err != nil || !strings.HasPrefix(string(md), "# Hardening Audit: testbox") {
		t.Errorf("markdown: %v %.50s", err, md)
	}
	if !strings.Contains(stdout, "Score:") || strings.Contains(stdout, "\x1b") {
		t.Errorf("plain report missing or colored:\n%s", stdout)
	}
}

func TestCLIJSONToStdoutSuppressesTextReport(t *testing.T) {
	code, stdout, _ := runCLI(t, "--root", fakeRoot(t), "--json", "-")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		t.Fatalf("stdout is not pure JSON: %v\n%s", err, stdout)
	}
	if _, ok := data["score"]; !ok {
		t.Error("no score in JSON")
	}
}

func TestCLIFailUnder(t *testing.T) {
	root := fakeRoot(t)
	if code, _, _ := runCLI(t, "--root", root, "--json", "-", "--fail-under", "101"); code != 1 {
		t.Errorf("score below threshold: exit %d, want 1", code)
	}
	if code, _, _ := runCLI(t, "--root", root, "--json", "-", "--fail-under", "0"); code != 0 {
		t.Errorf("score above threshold: exit %d, want 0", code)
	}
}

func TestCLIUnwritableOutputFails(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "nope", "out.json")
	code, _, stderr := runCLI(t, "--root", fakeRoot(t), "--json", bad)
	if code != 2 || !strings.Contains(stderr, "bulwark:") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

func TestCLIVersionAndBadFlag(t *testing.T) {
	if code, out, _ := runCLI(t, "--version"); code != 0 || !strings.Contains(out, version) {
		t.Errorf("--version: %d %q", code, out)
	}
	if code, _, _ := runCLI(t, "--bogus"); code != 2 {
		t.Errorf("bad flag: exit %d, want 2", code)
	}
}

func TestNonTerminalFallsBackToPlain(t *testing.T) {
	var buf bytes.Buffer
	if useTUI(options{}, &buf) {
		t.Error("a non-terminal writer must not get the TUI")
	}
}
