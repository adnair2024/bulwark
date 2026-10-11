package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write creates a file under the fake root with the given mode.
func write(t *testing.T, root, rel, text string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// fakeRunner maps a command prefix (space-joined argv) to a canned result.
// Commands matching no prefix report as not installed.
func fakeRunner(responses map[string]CmdResult) Runner {
	return func(cmd []string) (CmdResult, bool) {
		line := strings.Join(cmd, " ")
		for prefix, res := range responses {
			if strings.HasPrefix(line, prefix) {
				return res, true
			}
		}
		return CmdResult{}, false
	}
}

func goodCmds() map[string]CmdResult {
	return map[string]CmdResult{
		"ufw status":                   {0, "Status: active\n"},
		"apt list --upgradable":        {0, "Listing... Done\n"},
		"systemctl is-active auditd":   {0, "active\n"},
		"systemctl is-active fail2ban": {0, "active\n"},
	}
}

func with(base map[string]CmdResult, overrides map[string]CmdResult) map[string]CmdResult {
	out := map[string]CmdResult{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

// hardenedRoot builds a minimal, well-hardened fake Ubuntu host.
func hardenedRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n", 0o644)
	write(t, root, "etc/hostname", "testbox\n", 0o644)
	write(t, root, "etc/passwd",
		"root:x:0:0:root:/root:/bin/bash\nashwin:x:1000:1000::/home/ashwin:/bin/bash\n", 0o644)
	write(t, root, "etc/shadow", "root:!:19000::::::\nashwin:$6$abc$def:19000::::::\n", 0o640)
	write(t, root, "etc/group", "sudo:x:27:ashwin\nashwin:x:1000:\n", 0o644)
	write(t, root, "etc/ssh/sshd_config",
		"PermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\n", 0o600)
	write(t, root, "etc/apt/apt.conf.d/20auto-upgrades",
		"APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n", 0o644)
	for k, v := range map[string]string{
		"kernel/randomize_va_space":          "2",
		"net/ipv4/ip_forward":                "0",
		"net/ipv4/tcp_syncookies":            "1",
		"net/ipv4/conf/all/accept_redirects": "0",
		"net/ipv4/conf/all/send_redirects":   "0",
		"kernel/dmesg_restrict":              "1",
		"kernel/kptr_restrict":               "1",
		"fs/protected_symlinks":              "1",
		"fs/protected_hardlinks":             "1",
	} {
		write(t, root, "proc/sys/"+k, v+"\n", 0o644)
	}
	// Listening: 0.0.0.0:22 and 127.0.0.1:5432
	write(t, root, "proc/net/tcp",
		"  sl  local_address rem_address   st\n"+
			"   0: 00000000:0016 00000000:0000 0A\n"+
			"   1: 0100007F:1538 00000000:0000 0A\n", 0o644)
	if err := os.Mkdir(filepath.Join(root, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "tmp"), os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	return root
}

func newSystem(root string, cmds map[string]CmdResult, isRoot bool) *System {
	return &System{Root: root, IsRoot: isRoot, Runner: fakeRunner(cmds)}
}

// resultsFor runs every check and indexes the results by ID.
func resultsFor(root string, cmds map[string]CmdResult, isRoot bool) map[string]Result {
	out := map[string]Result{}
	for _, r := range RunAll(newSystem(root, cmds, isRoot)) {
		out[r.ID] = r
	}
	return out
}

func wantStatus(t *testing.T, res map[string]Result, want Status, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if res[id].Status != want {
			t.Errorf("%s = %s (%s), want %s", id, res[id].Status, res[id].Detail, want)
		}
	}
}
