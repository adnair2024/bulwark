package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHardenedHostHasNoFailures(t *testing.T) {
	res := resultsFor(hardenedRoot(t), goodCmds(), true)
	for id, r := range res {
		if r.Status == Fail && id != "SSH-06" { // SSH-06 depends on the file owner
			t.Errorf("%s failed: %s", id, r.Detail)
		}
	}
	if len(res) != 27 {
		t.Errorf("got %d checks, want 27", len(res))
	}
}

func TestEveryFailAndWarnHasAFix(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/ssh/sshd_config", "PermitRootLogin yes\nMaxAuthTries 9\nX11Forwarding yes\n", 0o666)
	write(t, root, "proc/sys/kernel/dmesg_restrict", "0\n", 0o644)
	for _, r := range resultsFor(root, goodCmds(), true) {
		if (r.Status == Fail || r.Status == Warn) && r.Remediation == "" {
			t.Errorf("%s is %s without a fix", r.ID, r.Status)
		}
	}
}

func TestCheckIDsAreUniqueAndOrdered(t *testing.T) {
	seen := map[string]bool{}
	var cats []string
	for _, c := range AllChecks() {
		if seen[c.ID] {
			t.Errorf("duplicate ID %s", c.ID)
		}
		seen[c.ID] = true
		if len(cats) == 0 || cats[len(cats)-1] != c.Category {
			cats = append(cats, c.Category)
		}
	}
	if got := strings.Join(cats, ","); got != "SSH,Accounts,Files,Network,Kernel,Updates,Logging" {
		t.Errorf("category order = %s", got)
	}
}

func TestSSHWeakSettingsFail(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/ssh/sshd_config",
		"PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n", 0o666)
	wantStatus(t, resultsFor(root, goodCmds(), true), Fail, "SSH-01", "SSH-02", "SSH-03", "SSH-06")
}

func TestSSHDefaultsApplyWhenUnset(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/ssh/sshd_config", "# all defaults\n", 0o600)
	res := resultsFor(root, goodCmds(), true)
	wantStatus(t, res, Warn, "SSH-01", "SSH-04") // prohibit-password, MaxAuthTries 6
	wantStatus(t, res, Fail, "SSH-02")           // PasswordAuthentication yes
	wantStatus(t, res, Pass, "SSH-03", "SSH-05")
}

func TestSSHFirstValueWinsAndInclude(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/ssh/sshd_config",
		"Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n", 0o600)
	write(t, root, "etc/ssh/sshd_config.d/50-hardening.conf", "PasswordAuthentication no\n", 0o644)
	wantStatus(t, resultsFor(root, goodCmds(), true), Pass, "SSH-02")
}

func TestSSHRelativeIncludeAndMatchInIncludeStopsParsing(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/ssh/sshd_config",
		"Include conf.d/*.conf\nPasswordAuthentication yes\n", 0o600)
	write(t, root, "etc/ssh/conf.d/10.conf", "PermitRootLogin no\nMatch User x\n", 0o644)
	res := resultsFor(root, goodCmds(), true)
	wantStatus(t, res, Pass, "SSH-01")
	// The Match block in the include is still open, so the later line is conditional.
	wantStatus(t, res, Fail, "SSH-02") // falls back to the default 'yes'
	if !strings.Contains(res["SSH-02"].Detail, "Password logins") {
		t.Errorf("unexpected detail %q", res["SSH-02"].Detail)
	}
}

func TestSSHMatchBlockIsIgnored(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/ssh/sshd_config",
		"PasswordAuthentication no\nMatch User guest\n  PasswordAuthentication yes\n", 0o600)
	wantStatus(t, resultsFor(root, goodCmds(), true), Pass, "SSH-02")
}

func TestSSHIncludeLoopTerminates(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/ssh/sshd_config", "Include /etc/ssh/sshd_config\nPasswordAuthentication no\n", 0o600)
	wantStatus(t, resultsFor(root, goodCmds(), true), Pass, "SSH-02")
}

func TestSSHUsesSshdTAsRoot(t *testing.T) {
	root := hardenedRoot(t) // file says hardened; sshd -T says otherwise
	cmds := with(goodCmds(), map[string]CmdResult{
		"sshd -T": {0, "permitrootlogin yes\npasswordauthentication no\nmaxauthtries 2\n"},
	})
	wantStatus(t, resultsFor(root, cmds, true), Fail, "SSH-01")
	// Without root, sshd -T is not used and the file is parsed.
	wantStatus(t, resultsFor(root, cmds, false), Pass, "SSH-01")
}

func TestSSHBadMaxAuthTries(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/ssh/sshd_config", "MaxAuthTries lots\n", 0o600)
	wantStatus(t, resultsFor(root, goodCmds(), true), Warn, "SSH-04")
}

func TestNoSSHServerSkips(t *testing.T) {
	root := hardenedRoot(t)
	if err := os.Remove(filepath.Join(root, "etc/ssh/sshd_config")); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, resultsFor(root, goodCmds(), true), Skip,
		"SSH-01", "SSH-02", "SSH-03", "SSH-04", "SSH-05", "SSH-06", "LOG-02")
}

func TestExtraUIDZeroAndEmptyPassword(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/passwd", "root:x:0:0::/root:/bin/sh\ntoor:x:0:0::/root:/bin/sh\n", 0o644)
	write(t, root, "etc/shadow", "root:!:1::::::\ntoor::1::::::\n", 0o640)
	res := resultsFor(root, goodCmds(), true)
	for _, id := range []string{"ACC-01", "ACC-02"} {
		if res[id].Status != Fail || !strings.Contains(res[id].Detail, "toor") {
			t.Errorf("%s = %s %q", id, res[id].Status, res[id].Detail)
		}
	}
}

func TestAccountsPassOnHardenedHost(t *testing.T) {
	res := resultsFor(hardenedRoot(t), goodCmds(), true)
	wantStatus(t, res, Pass, "ACC-01", "ACC-02")
	wantStatus(t, res, Info, "ACC-03")
	if !strings.Contains(res["ACC-03"].Detail, "ashwin") {
		t.Errorf("ACC-03 detail %q", res["ACC-03"].Detail)
	}
}

func TestUnreadablePasswdAndGroupSkip(t *testing.T) {
	root := hardenedRoot(t)
	for _, f := range []string{"etc/passwd", "etc/group"} {
		if err := os.Remove(filepath.Join(root, f)); err != nil {
			t.Fatal(err)
		}
	}
	wantStatus(t, resultsFor(root, goodCmds(), true), Skip, "ACC-01", "ACC-03", "FILE-01")
}

func TestUnreadableShadowSkipsWithSudoHint(t *testing.T) {
	root := hardenedRoot(t)
	if err := os.Remove(filepath.Join(root, "etc/shadow")); err != nil {
		t.Fatal(err)
	}
	res := resultsFor(root, goodCmds(), false)
	if res["ACC-02"].Status != Skip || !strings.Contains(res["ACC-02"].Detail, "sudo") {
		t.Errorf("non-root: %s %q", res["ACC-02"].Status, res["ACC-02"].Detail)
	}
	res = resultsFor(root, goodCmds(), true)
	if res["ACC-02"].Status != Skip || strings.Contains(res["ACC-02"].Detail, "sudo") {
		t.Errorf("root: %s %q", res["ACC-02"].Status, res["ACC-02"].Detail)
	}
}

func TestWorldWritableEtcDetected(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/bad.conf", "x", 0o666)
	res := resultsFor(root, goodCmds(), true)
	if res["FILE-03"].Status != Fail || !strings.Contains(res["FILE-03"].Detail, "/etc/bad.conf") {
		t.Errorf("FILE-03 = %s %q", res["FILE-03"].Status, res["FILE-03"].Detail)
	}
}

func TestWorldWritableEtcIgnoresSymlinksAndStickyDirs(t *testing.T) {
	root := hardenedRoot(t)
	if err := os.Symlink("/nonexistent", filepath.Join(root, "etc/link")); err != nil {
		t.Fatal(err)
	}
	sticky := filepath.Join(root, "etc/shared")
	if err := os.Mkdir(sticky, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, resultsFor(root, goodCmds(), true), Pass, "FILE-03")
}

func TestWorldWritableEtcTruncatesLongList(t *testing.T) {
	root := hardenedRoot(t)
	for i := 0; i < 12; i++ {
		write(t, root, filepath.Join("etc", "bad", string(rune('a'+i))), "x", 0o666)
	}
	d := resultsFor(root, goodCmds(), true)["FILE-03"].Detail
	if !strings.Contains(d, "12 world-writable") || !strings.Contains(d, "(+2 more)") {
		t.Errorf("detail %q", d)
	}
}

func TestPasswdPermissions(t *testing.T) {
	root := hardenedRoot(t)
	wantStatus(t, resultsFor(root, goodCmds(), true), Pass, "FILE-01")
	if err := os.Chmod(filepath.Join(root, "etc/passwd"), 0o666); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, resultsFor(root, goodCmds(), true), Fail, "FILE-01")
}

func TestShadowWorldReadableFails(t *testing.T) {
	root := hardenedRoot(t)
	if err := os.Chmod(filepath.Join(root, "etc/shadow"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, resultsFor(root, goodCmds(), true), Fail, "FILE-02")
}

func TestShadowMissingSkips(t *testing.T) {
	root := hardenedRoot(t)
	if err := os.Remove(filepath.Join(root, "etc/shadow")); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, resultsFor(root, goodCmds(), true), Skip, "FILE-02")
}

func TestTmpWithoutStickyBitFails(t *testing.T) {
	root := hardenedRoot(t)
	if err := os.Chmod(filepath.Join(root, "tmp"), 0o777); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, resultsFor(root, goodCmds(), true), Fail, "FILE-04")
	if err := os.Remove(filepath.Join(root, "tmp")); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, resultsFor(root, goodCmds(), true), Skip, "FILE-04")
}

func TestFirewallBackends(t *testing.T) {
	root := hardenedRoot(t)
	none := map[string]CmdResult{}
	tests := []struct {
		name string
		cmds map[string]CmdResult
		root bool
		want Status
	}{
		{"ufw active", goodCmds(), true, Pass},
		{"firewalld", map[string]CmdResult{"firewall-cmd --state": {0, "running\n"}}, true, Pass},
		{"nftables rules", map[string]CmdResult{"nft list ruleset": {0, "table inet f {\n chain input {\n  type filter hook input priority 0;\n  tcp dport 22 accept\n }\n}\n"}}, true, Pass},
		{"nftables drop policy", map[string]CmdResult{"nft list ruleset": {0, "table inet f {\n chain input {\n  type filter hook input priority 0; policy drop;\n }\n}\n"}}, true, Pass},
		{"nftables empty", map[string]CmdResult{"nft list ruleset": {0, "table inet f {\n chain input {\n  type filter hook input priority 0; policy accept;\n }\n}\n"}}, true, Fail},
		{"iptables rules", map[string]CmdResult{"iptables -S": {0, "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n"}}, true, Pass},
		{"iptables drop policy", map[string]CmdResult{"iptables -S": {0, "-P INPUT DROP\n"}}, true, Pass},
		{"iptables open", map[string]CmdResult{
			"ufw status":  {0, "Status: inactive\n"},
			"iptables -S": {0, "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"}}, true, Fail},
		{"nothing, root", none, true, Fail},
		{"nothing, not root", none, false, Warn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantStatus(t, resultsFor(root, tt.cmds, tt.root), tt.want, "NET-01")
		})
	}
}

func TestRiskyPortExposed(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "proc/net/tcp", "header\n   0: 00000000:18EB 00000000:0000 0A\n", 0o644) // Redis 6379
	res := resultsFor(root, goodCmds(), true)
	if res["NET-02"].Status != Fail || !strings.Contains(res["NET-02"].Detail, "Redis") {
		t.Errorf("NET-02 = %s %q", res["NET-02"].Status, res["NET-02"].Detail)
	}
}

func TestLoopbackAndNonListeningAreIgnored(t *testing.T) {
	root := hardenedRoot(t)
	// Postgres on loopback, and an ESTABLISHED (01) socket on 6379.
	write(t, root, "proc/net/tcp",
		"header\n   0: 0100007F:1538 00000000:0000 0A\n"+
			"   1: 00000000:18EB 0A00000A:D431 01\n", 0o644)
	write(t, root, "proc/net/tcp6",
		"header\n   0: 00000000000000000000000001000000:18EB "+
			"00000000000000000000000000000000:0000 0A\n", 0o644)
	res := resultsFor(root, goodCmds(), true)
	wantStatus(t, res, Pass, "NET-02")
	if !strings.Contains(res["NET-02"].Detail, "ports: none") {
		t.Errorf("detail %q", res["NET-02"].Detail)
	}
}

func TestIPv6ExposedPortCounts(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "proc/net/tcp6",
		"header\n   0: 00000000000000000000000000000000:0017 "+
			"00000000000000000000000000000000:0000 0A\n", 0o644) // :::23 telnet
	res := resultsFor(root, goodCmds(), true)
	if res["NET-02"].Status != Fail || !strings.Contains(res["NET-02"].Detail, "Telnet") {
		t.Errorf("NET-02 = %s %q", res["NET-02"].Status, res["NET-02"].Detail)
	}
}

func TestNoProcNetSkips(t *testing.T) {
	root := hardenedRoot(t)
	if err := os.Remove(filepath.Join(root, "proc/net/tcp")); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, resultsFor(root, goodCmds(), true), Skip, "NET-02")
}

func TestSysctlFailures(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "proc/sys/kernel/randomize_va_space", "0\n", 0o644)
	write(t, root, "proc/sys/fs/protected_hardlinks", "0\n", 0o644)
	write(t, root, "proc/sys/net/ipv4/ip_forward", "1\n", 0o644)
	res := resultsFor(root, goodCmds(), true)
	wantStatus(t, res, Fail, "KRN-01")
	wantStatus(t, res, Warn, "KRN-02")
	if res["KRN-08"].Status != Fail || !strings.Contains(res["KRN-08"].Detail, "protected_hardlinks") {
		t.Errorf("KRN-08 = %s %q", res["KRN-08"].Status, res["KRN-08"].Detail)
	}
	if !strings.Contains(res["KRN-01"].Remediation, "kernel.randomize_va_space = 2") {
		t.Errorf("KRN-01 fix %q", res["KRN-01"].Remediation)
	}
}

func TestKptrRestrictAcceptsTwo(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "proc/sys/kernel/kptr_restrict", "2\n", 0o644)
	wantStatus(t, resultsFor(root, goodCmds(), true), Pass, "KRN-07")
}

func TestMissingSysctlsSkip(t *testing.T) {
	root := hardenedRoot(t)
	if err := os.RemoveAll(filepath.Join(root, "proc/sys")); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, resultsFor(root, goodCmds(), true), Skip,
		"KRN-01", "KRN-02", "KRN-03", "KRN-04", "KRN-05", "KRN-06", "KRN-07", "KRN-08")
}

func TestSecurityUpdatesFail(t *testing.T) {
	cmds := with(goodCmds(), map[string]CmdResult{"apt list --upgradable": {0,
		"Listing... Done\nopenssl/noble-security 3.0.13 amd64 [upgradable from: 3.0.10]\n" +
			"vim/noble-updates 9.1 amd64 [upgradable from: 9.0]\n"}})
	res := resultsFor(hardenedRoot(t), cmds, true)
	if res["UPD-01"].Status != Fail || !strings.Contains(res["UPD-01"].Detail, "1 security") {
		t.Errorf("UPD-01 = %s %q", res["UPD-01"].Status, res["UPD-01"].Detail)
	}
}

func TestNonSecurityUpdatesWarn(t *testing.T) {
	cmds := with(goodCmds(), map[string]CmdResult{"apt list --upgradable": {0,
		"Listing... Done\nvim/noble-updates 9.1 amd64 [upgradable from: 9.0]\n"}})
	wantStatus(t, resultsFor(hardenedRoot(t), cmds, true), Warn, "UPD-01")
}

func TestAptMissingSkips(t *testing.T) {
	cmds := map[string]CmdResult{}
	wantStatus(t, resultsFor(hardenedRoot(t), cmds, true), Skip, "UPD-01")
}

func TestArchUpdates(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/os-release", "ID=arch\nPRETTY_NAME=\"Arch Linux\"\n", 0o644)
	upToDate := with(goodCmds(), map[string]CmdResult{"checkupdates": {2, ""}})
	res := resultsFor(root, upToDate, true)
	wantStatus(t, res, Pass, "UPD-01")
	wantStatus(t, res, Skip, "UPD-02")
	pending := with(goodCmds(), map[string]CmdResult{"checkupdates": {0, "linux 6.10.1 -> 6.10.2\n"}})
	wantStatus(t, resultsFor(root, pending, true), Fail, "UPD-01")
	failed := with(goodCmds(), map[string]CmdResult{"checkupdates": {1, ""}})
	wantStatus(t, resultsFor(root, failed, true), Skip, "UPD-01")
	wantStatus(t, resultsFor(root, goodCmds(), true), Skip, "UPD-01") // checkupdates not installed
}

func TestFedoraUpdates(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/os-release", "ID=fedora\nPRETTY_NAME=\"Fedora Linux 41\"\n", 0o644)
	cases := map[int]Status{0: Pass, 100: Warn, 1: Skip}
	for code, want := range cases {
		cmds := with(goodCmds(), map[string]CmdResult{"dnf check-update": {code, "kernel 6.1 updates\n"}})
		wantStatus(t, resultsFor(root, cmds, true), want, "UPD-01")
	}
}

func TestUnknownDistroSkipsUpdates(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/os-release", "ID=plan9\n", 0o644)
	wantStatus(t, resultsFor(root, goodCmds(), true), Skip, "UPD-01", "UPD-02")
}

func TestDerivativeDistroUsesIDLike(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/os-release", "ID=manjaro\nID_LIKE=arch\n", 0o644)
	cmds := with(goodCmds(), map[string]CmdResult{"checkupdates": {2, ""}})
	wantStatus(t, resultsFor(root, cmds, true), Pass, "UPD-01")
}

func TestAutoUpdatesDisabledWarns(t *testing.T) {
	root := hardenedRoot(t)
	write(t, root, "etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Unattended-Upgrade \"0\";\n", 0o644)
	wantStatus(t, resultsFor(root, goodCmds(), true), Warn, "UPD-02")
}

func TestAuditdStates(t *testing.T) {
	root := hardenedRoot(t)
	inactive := with(goodCmds(), map[string]CmdResult{"systemctl is-active auditd": {3, "inactive\n"}})
	wantStatus(t, resultsFor(root, inactive, true), Warn, "LOG-01")
	noSystemd := map[string]CmdResult{"ufw status": {0, "Status: active\n"}}
	wantStatus(t, resultsFor(root, noSystemd, true), Skip, "LOG-01", "LOG-02")
}

func TestNoBruteforceProtectionWarns(t *testing.T) {
	cmds := with(goodCmds(), map[string]CmdResult{
		"systemctl is-active fail2ban": {3, "inactive\n"},
		"systemctl is-active sshguard": {3, "inactive\n"},
		"systemctl is-active crowdsec": {3, "inactive\n"},
	})
	wantStatus(t, resultsFor(hardenedRoot(t), cmds, true), Warn, "LOG-02")
}

func TestBruteforceProtectionNamesTheService(t *testing.T) {
	cmds := with(goodCmds(), map[string]CmdResult{
		"systemctl is-active fail2ban": {3, "inactive\n"},
		"systemctl is-active sshguard": {3, "inactive\n"},
		"systemctl is-active crowdsec": {0, "active\n"},
	})
	res := resultsFor(hardenedRoot(t), cmds, true)
	if res["LOG-02"].Status != Pass || !strings.Contains(res["LOG-02"].Detail, "crowdsec") {
		t.Errorf("LOG-02 = %s %q", res["LOG-02"].Status, res["LOG-02"].Detail)
	}
}

func r(status Status, sev Severity) Result {
	return Result{ID: "X", Category: "c", Title: "t", Severity: sev, Status: status, Detail: "d"}
}

func TestScoring(t *testing.T) {
	tests := []struct {
		name    string
		results []Result
		pct     int
		grade   string
	}{
		{"all pass", []Result{r(Pass, High), r(Pass, Low)}, 100, "A"},
		{"half", []Result{r(Pass, High), r(Fail, High)}, 50, "F"},
		{"warn is half", []Result{r(Warn, Medium)}, 50, "F"},
		{"skip and info ignored", []Result{r(Pass, Low), r(Skip, High), r(Info, Low)}, 100, "A"},
		{"empty", nil, 0, "F"},
		{"B", []Result{r(Pass, High), r(Pass, High), r(Pass, High), r(Pass, High), r(Fail, Medium)}, 86, "B"},
		{"C", []Result{r(Pass, High), r(Pass, Low), r(Fail, Low), r(Pass, Medium), r(Fail, Medium)}, 67, "D"},
		{"banker's rounding like Python", []Result{r(Pass, Low), r(Fail, Low), r(Fail, Low), r(Fail, Low),
			r(Fail, Low), r(Fail, Low), r(Fail, Low), r(Fail, Low)}, 12, "F"}, // 12.5 rounds to 12
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pct, grade := Score(tt.results)
			if pct != tt.pct || grade != tt.grade {
				t.Errorf("Score = %d, %s; want %d, %s", pct, grade, tt.pct, tt.grade)
			}
		})
	}
}

func TestGradeBoundaries(t *testing.T) {
	// n passing low-severity checks out of 100.
	for pct, want := range map[int]string{90: "A", 89: "B", 80: "B", 79: "C", 70: "C", 69: "D", 60: "D", 59: "F"} {
		results := make([]Result, 100)
		for i := range results {
			status := Fail
			if i < pct {
				status = Pass
			}
			results[i] = r(status, Low)
		}
		if got, grade := Score(results); got != pct || grade != want {
			t.Errorf("%d%% -> %d, %s; want %s", pct, got, grade, want)
		}
	}
}

func TestBrokenCheckDoesNotCrash(t *testing.T) {
	c := Check{"T-01", "Test", "broken", Low, func(*System) Outcome { panic("kaboom") }}
	got := RunCheck(newSystem(t.TempDir(), nil, false), c)
	if got.Status != Skip || !strings.Contains(got.Detail, "kaboom") {
		t.Errorf("got %s %q", got.Status, got.Detail)
	}
}

func TestSystemRunWithoutRunner(t *testing.T) {
	s := NewSystem(t.TempDir())
	if _, ok := s.Run("ufw", "status"); ok {
		t.Error("commands must not run against a fake root")
	}
}
