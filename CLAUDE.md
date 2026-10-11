# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

**bulwark** is a read-only Linux hardening auditor with a terminal UI. It checks a host against common CIS-inspired security controls (SSH, accounts, file permissions, firewall, exposed services, kernel parameters, patching, logging), scores the result, and shows a concrete fix for every finding.

It ships as a single static Go binary so it can be copied to any Linux box and run directly. Target distros: Debian/Ubuntu, Arch, and Fedora/RHEL. The author runs Arch and Ubuntu, so every change must work on both.

### Current state

The Go rewrite is complete: all 27 checks, all output formats (TUI, plain, JSON, Markdown), and the tests are ported from the original Python tool, which has been removed. Check IDs, messages, and remediation text are stable; keep them unless a change is deliberate.

## Stack

- **Go 1.24+**, standard library for all audit logic
- **[Bubble Tea](https://github.com/charmbracelet/bubbletea)** (v1.3.x) for the interactive TUI
- **[Lip Gloss](https://github.com/charmbracelet/lipgloss)** (v1.1.x) for all styling and layout, in the TUI and the plain-text report
- **[Bubbles](https://github.com/charmbracelet/bubbles)** (v1.x) for the spinner, progress bar, key bindings, and help line

Don't add dependencies beyond the Charm libraries (and what they pull in) without asking. Tests use the standard `testing` package only.

## Layout

```
main.go                 flags, mode selection (TUI vs. plain), file output, exit codes
internal/audit/         audit engine; no TUI or Charm imports here except Lip Gloss in report.go
  system.go             System: the only access to the filesystem and commands
  check.go              Result, Status, Severity, AllChecks(), RunCheck(), Score()
  ssh.go accounts.go files.go network.go kernel.go updates.go logging.go
  report.go             plain-text (Lip Gloss), Markdown, and JSON output
  *_test.go
internal/tui/           Bubble Tea model, views, and Lip Gloss styles
```

Module path: `github.com/adnair2024/bulwark`.

## Commands

```bash
go build -o bulwark .           # build the binary
sudo ./bulwark                  # interactive TUI (root gives full coverage)
./bulwark --plain               # static styled report, no TUI
./bulwark --json - | jq .score  # JSON to stdout
./bulwark --markdown report.md  # write a Markdown report
./bulwark --fail-under 80       # exit 1 if score < 80 (cron/CI)
go test ./...                   # run all tests (no root needed)
go vet ./... && gofmt -l .      # must be clean before committing
```

Release builds should be static: `CGO_ENABLED=0 go build -ldflags="-s -w" -o bulwark .`

## Hard rules

- **Read-only, always.** Only read files and run query commands (`ufw status`, `apt list --upgradable`, `systemctl is-active`, `sshd -T`, and similar). Never add code that changes the system: no fixes applied, no `chmod`, no config writes, no service restarts. Remediation is text for a human to review. The one exception is writing report files the user explicitly asks for (`--json`, `--markdown`, or the TUI export key).
- **Never crash the audit.** `RunCheck` recovers from panics and records them as SKIP. Checks should still handle missing files and commands gracefully on their own.
- **The engine doesn't know about the TUI.** `internal/audit` must stay usable without Bubble Tea, so the plain, JSON, and Markdown modes and the tests don't depend on a terminal.

## Engine architecture (`internal/audit`)

- **`System`** is the only way checks touch the machine. `Read`, `Stat`, `Exists`, `Sysctl`, and `OSRelease` resolve paths under `System.Root`; `System.Run` executes commands and returns `(CmdResult, ok)`, with `ok == false` if the binary isn't installed. Never call `os.ReadFile`, `os.Stat`, or `exec` directly from a check.
- **Checks** are `Check{ID, Category, Title, Severity, Fn}` values in per-category slices (`sshChecks`, `accountChecks`, ...). `AllChecks()` concatenates them in a fixed order; that order is the run and display order. Don't use `init()` registration, since Go initializes files alphabetically and would scramble the order.
- **Check functions** take `*System` and return an `Outcome` via the helpers `pass`, `fail`, `warn`, `skip`, `info`. Use `needsRoot(s, what)` when data requires root.
- **Statuses**: PASS, FAIL, WARN, SKIP (can't run or not applicable), INFO (review-only, not scored).
- **Scoring** (`Score`): weights high = 3, medium = 2, low = 1. PASS earns full weight, WARN half, FAIL zero; SKIP and INFO are excluded. Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F. Changing weights or thresholds changes every user's score, so only do it deliberately and update the README.
- **SSH parsing**: prefer `sshd -T` when root. Otherwise parse `sshd_config` like sshd does: first value wins, `Include` is expanded in place, stop at the first `Match` block, then overlay OpenSSH defaults for unset keys.
- **Network exposure** comes from `/proc/net/tcp` and `/proc/net/tcp6` (state `0A` = LISTEN), not from `ss` or `netstat`.

## TUI (`internal/tui`)

- **Running state**: a spinner plus a progress bar, running one check per `tea.Cmd` so the bar advances as each check finishes.
- **Results state**: a header (host, OS, root/non-root notice), a score panel (big score, color-coded grade, status counts), a scrollable check list grouped by category, and a detail pane for the selected check (detail plus a boxed fix). Side by side on wide terminals, stacked on narrow ones.
- **Keys**: `↑/↓` or `j/k` move, `f` cycles filters (all, issues, fail, warn, pass), `m` exports a Markdown report, `q` or `ctrl+c` quits. Show them with the Bubbles help component.
- After the TUI exits (alt screen), print a one-line summary to the normal terminal so the result isn't lost.
- Fall back to the plain report automatically when stdout isn't a TTY, with `--plain`, or with `--json -`.
- Define all styles in one `styles.go`. Use `lipgloss.AdaptiveColor` so it reads well on light and dark terminals, and respect `--no-color` and `NO_COLOR`. Status colors: PASS green, FAIL red, WARN yellow, SKIP gray, INFO cyan.
- Handle `tea.WindowSizeMsg`, and keep views from overflowing the terminal width.

## Adding a check

1. Use the next ID in the category (`SSH-07`, `KRN-09`, ...). IDs are stable: never renumber or reuse one, since users compare reports over time.
2. Add the `Check` to its category's slice. `Detail` is one sentence stating what was found. Every FAIL and WARN gets a `Fix` with a concrete command or config line.
3. Choose severity honestly: high = directly exploitable or exposes credentials; medium = meaningful weakening; low = defense-in-depth.
4. Add tests for at least the passing, failing, and SKIP cases.
5. Add a row to the checks table in `README.md`.

## Testing

- Tests never touch the real system. Build a fake root with `t.TempDir()` and write files into it, and fake command output with a `Runner` keyed by command prefix.
- Keep a shared "fully hardened host" fixture; the test asserting it has no failures must keep passing (SSH-06 excepted, since it depends on the file owner of whoever runs the tests).
- Test both `IsRoot: true` and `IsRoot: false` when a check behaves differently without root.
- Test the TUI model by sending messages to `Update` and asserting on state and `View()` output. Don't spin up a real program.

## Style

- `gofmt`, `go vet`, and idiomatic Go: small functions, early returns, errors handled rather than ignored (except deliberate best-effort reads).
- User-facing text is plain and specific: say what was found and what to do, not vague phrases like "may be insecure."
- Bump the version constant in `main.go` when check behavior or output format changes.

## TODO:
- [x] Add distro logo (popular distros)
- [ ] Add option to fix most simple security checks that are failing
- [ ] Explain how to run as sudo somewhere, maybe a mini help page when `h` is toggled

