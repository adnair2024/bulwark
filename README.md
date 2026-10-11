# bulwark

A read-only Linux hardening auditor with a terminal UI. It checks a host against common security controls inspired by the [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) (SSH, accounts, file permissions, firewall, exposed services, kernel parameters, patching, logging), scores the result, and shows a concrete fix for every finding.

Ships as a single static Go binary: copy it to any Linux box and run it. It never changes your system.

Supports Debian/Ubuntu, Arch, and Fedora/RHEL-family systems.

## Usage

```bash
go build -o bulwark .
sudo ./bulwark                  # interactive TUI (root gives full coverage)
./bulwark --plain               # static styled report, no TUI
./bulwark --json - | jq .score  # JSON to stdout
./bulwark --json results.json   # JSON to a file
./bulwark --markdown report.md  # write a Markdown report
./bulwark --fail-under 80       # exit 1 if score < 80 (cron/CI)
./bulwark --no-color            # disable color (NO_COLOR is also respected)
```

The TUI falls back to the plain report automatically when stdout isn't a terminal, with `--plain`, or with `--json -`.

TUI keys: `↑/↓` or `j/k` move, `f` cycles filters (all, issues, fail, warn, pass), `m` exports a Markdown report to `bulwark-report.md`, `q` or `ctrl+c` quits.

Run with `sudo` for full coverage. Without root it still works, but checks that need privileged data (like `/etc/shadow` or firewall rules) are skipped or downgraded, and the report says so.

Release build:

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o bulwark .
```

## What it checks

| ID | Check | Severity |
|---|---|---|
| SSH-01 | Root login over SSH is disabled | high |
| SSH-02 | SSH password authentication is disabled | high |
| SSH-03 | SSH does not allow empty passwords | high |
| SSH-04 | SSH limits authentication attempts (MaxAuthTries ≤ 4) | low |
| SSH-05 | SSH X11 forwarding is disabled | low |
| SSH-06 | sshd_config is owned by root and not writable by others | medium |
| ACC-01 | Only root has UID 0 | high |
| ACC-02 | No accounts have an empty password | high |
| ACC-03 | Lists administrative (sudo/wheel) users for review | info |
| FILE-01 | /etc/passwd is not writable by group/others | medium |
| FILE-02 | /etc/shadow is not readable by other users | high |
| FILE-03 | No world-writable files in /etc | medium |
| FILE-04 | /tmp has the sticky bit set | medium |
| NET-01 | A host firewall is active (ufw, firewalld, nftables, or iptables) | high |
| NET-02 | No risky services (Telnet, FTP, SMB, Redis, databases…) exposed to the network | high |
| KRN-01 | ASLR is fully enabled | medium |
| KRN-02 | IP forwarding is disabled (warning only; needed on Docker/VM hosts) | low |
| KRN-03 | TCP SYN cookies are enabled | low |
| KRN-04 | ICMP redirects are not accepted | low |
| KRN-05 | ICMP redirects are not sent | low |
| KRN-06 | Kernel logs (dmesg) are restricted to root | low |
| KRN-07 | Kernel pointers are hidden | low |
| KRN-08 | Symlink and hardlink protections are enabled | medium |
| UPD-01 | No pending package updates (security updates flagged on Debian/Ubuntu) | high |
| UPD-02 | Automatic security updates are enabled (Debian/Ubuntu) | medium |
| LOG-01 | System auditing (auditd) is running | low |
| LOG-02 | SSH brute-force protection (fail2ban, sshguard, or CrowdSec) is running | medium |

Check IDs are stable so reports can be compared over time.

## How scoring works

Each check has a severity weight: high = 3, medium = 2, low = 1. A pass earns the full weight, a warning earns half, and a failure earns nothing. Skipped and informational checks don't count. The score is the percentage of possible points earned (rounded half to even), graded A (90+), B (80+), C (70+), D (60+), else F.

## Design notes

- **Read-only by design.** bulwark only reads files and runs query commands (`ufw status`, `apt list --upgradable`, `systemctl is-active`, `sshd -T`). It never applies fixes; remediation steps are printed for a human to review. The only files it writes are reports you ask for.
- **Reads SSH config the way sshd does.** As root it uses `sshd -T` for the real effective configuration. Otherwise it parses `sshd_config` itself: first value wins, `Include` is expanded in place, parsing stops at the first `Match` block, and OpenSSH defaults fill unset options.
- **Finds exposed services without extra tools.** Listening sockets come straight from `/proc/net/tcp` and `/proc/net/tcp6`, separating services bound to all interfaces from those bound only to localhost.
- **Fails safely.** If a check panics, it's reported as skipped and the rest of the audit continues.
- **Testable.** All system access goes through one `System` type, so tests run every check against a fake filesystem and fake command output. They need no root and never touch the real system.

## Development

```bash
go test ./...                 # no root needed
go vet ./... && gofmt -l .    # must be clean
```

The audit engine lives in `internal/audit` and has no TUI dependency; the Bubble Tea front end is in `internal/tui`.

## Roadmap

- Check for SUID/SGID binaries outside a known-good list
- Password aging and PAM password-quality policy
- Mount options (`noexec`/`nosuid` on `/tmp`, `/dev/shm`)
- Compare two JSON reports to show what changed between runs

## Disclaimer

These checks cover common baseline controls and are not a complete CIS Benchmark assessment. Review each fix before applying it, especially SSH changes on a remote machine: make sure key-based login works first so you don't lock yourself out.

## License

MIT
