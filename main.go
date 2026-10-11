// bulwark is a read-only Linux hardening auditor with a terminal UI.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/adnair2024/bulwark/internal/audit"
	"github.com/adnair2024/bulwark/internal/tui"
)

const version = "0.2.0"

const exportFile = "bulwark-report.md"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	jsonPath     string
	markdownPath string
	failUnder    int
	noColor      bool
	plain        bool
	root         string
}

func run(args []string, stdout, stderr io.Writer) int {
	var opts options
	var showVersion bool
	fs := flag.NewFlagSet("bulwark", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: bulwark [flags]\n\nAudit a Linux host against common hardening controls. Read-only.\n\nFlags:")
		fs.PrintDefaults()
	}
	fs.StringVar(&opts.jsonPath, "json", "", "write results as JSON to `FILE` ('-' for stdout)")
	fs.StringVar(&opts.markdownPath, "markdown", "", "write a Markdown report to `FILE`")
	fs.IntVar(&opts.failUnder, "fail-under", -1, "exit with status 1 if the score is below `SCORE`")
	fs.BoolVar(&opts.noColor, "no-color", false, "disable colored output")
	fs.BoolVar(&opts.plain, "plain", false, "print a static report instead of the interactive UI")
	fs.StringVar(&opts.root, "root", "/", "audit a filesystem rooted at `DIR` (for testing)")
	fs.BoolVar(&showVersion, "version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if showVersion {
		fmt.Fprintln(stdout, "bulwark", version)
		return 0
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(stderr, "bulwark only supports Linux.")
		return 2
	}
	if opts.noColor {
		// Must be set before Lip Gloss first detects the color profile.
		os.Setenv("NO_COLOR", "1")
	}

	sys := audit.NewSystem(opts.root)
	meta := audit.BuildMeta(sys, version)

	var results []audit.Result
	if useTUI(opts, stdout) {
		results = runTUI(sys, meta, stdout, stderr)
	} else {
		results = audit.RunAll(sys)
		if opts.jsonPath != "-" {
			color := !opts.noColor && isTerminal(stdout) && os.Getenv("NO_COLOR") == ""
			fmt.Fprintln(stdout, audit.RenderText(results, meta, color))
		}
	}

	code := 0
	if err := writeReports(opts, results, meta, stdout); err != nil {
		fmt.Fprintln(stderr, "bulwark:", err)
		code = 2
	}
	if pct, _ := audit.Score(results); opts.failUnder >= 0 && pct < opts.failUnder && code == 0 {
		code = 1
	}
	return code
}

// useTUI picks the interactive UI unless a static report was asked for or
// stdout/stdin isn't a terminal.
func useTUI(opts options, stdout io.Writer) bool {
	return !opts.plain && opts.jsonPath != "-" && isTerminal(stdout) && isTerminal(os.Stdin)
}

func runTUI(sys *audit.System, meta audit.Meta, stdout, stderr io.Writer) []audit.Result {
	final, err := tea.NewProgram(tui.New(sys, meta, exportFile), tea.WithAltScreen()).Run()
	if err != nil {
		fmt.Fprintln(stderr, "bulwark: interactive UI failed:", err)
		return audit.RunAll(sys)
	}
	m := final.(tui.Model)
	fmt.Fprintln(stdout, m.Summary())
	if !m.Done() { // quit early: finish the audit so --json/--markdown/--fail-under are complete
		return audit.RunAll(sys)
	}
	return m.Results()
}

func writeReports(opts options, results []audit.Result, meta audit.Meta, stdout io.Writer) error {
	if opts.jsonPath != "" {
		payload, err := audit.RenderJSON(results, meta)
		if err != nil {
			return err
		}
		if opts.jsonPath == "-" {
			fmt.Fprintln(stdout, payload)
		} else if err := os.WriteFile(opts.jsonPath, []byte(payload+"\n"), 0o644); err != nil {
			return err
		}
	}
	if opts.markdownPath != "" {
		return os.WriteFile(opts.markdownPath, []byte(audit.RenderMarkdown(results, meta)), 0o644)
	}
	return nil
}

func isTerminal(w any) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
