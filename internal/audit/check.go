package audit

import (
	"fmt"
	"math"
)

type Status string

const (
	Pass Status = "PASS"
	Fail Status = "FAIL"
	Warn Status = "WARN"
	Skip Status = "SKIP" // can't run or not applicable
	Info Status = "INFO" // review-only, not scored
)

type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
)

// Weight is the severity's share of the score.
func (v Severity) Weight() int {
	switch v {
	case High:
		return 3
	case Medium:
		return 2
	}
	return 1
}

// Outcome is what a check function returns.
type Outcome struct {
	Status Status
	Detail string
	Fix    string
}

func pass(detail string) Outcome      { return Outcome{Status: Pass, Detail: detail} }
func fail(detail, fix string) Outcome { return Outcome{Fail, detail, fix} }
func warn(detail, fix string) Outcome { return Outcome{Warn, detail, fix} }
func skip(detail string) Outcome      { return Outcome{Status: Skip, Detail: detail} }
func info(detail string) Outcome      { return Outcome{Status: Info, Detail: detail} }

// needsRoot is the SKIP outcome for data that couldn't be read.
func needsRoot(s *System, what string) Outcome {
	if s.IsRoot {
		return skip(fmt.Sprintf("Could not read %s.", what))
	}
	return skip(fmt.Sprintf("Could not read %s; run with sudo for this check.", what))
}

type Check struct {
	ID       string
	Category string
	Title    string
	Severity Severity
	Fn       func(*System) Outcome
}

// Result is a Check's recorded outcome.
type Result struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Status      Status   `json:"status"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation"`
}

// AllChecks lists every check in run and display order.
func AllChecks() []Check {
	var all []Check
	for _, group := range [][]Check{
		sshChecks, accountChecks, fileChecks, networkChecks,
		kernelChecks, updateChecks, loggingChecks,
	} {
		all = append(all, group...)
	}
	return all
}

// RunCheck runs one check. A panic is recorded as SKIP so one broken check
// can't kill the audit.
func RunCheck(s *System, c Check) (r Result) {
	defer func() {
		if p := recover(); p != nil {
			r = newResult(c, skip(fmt.Sprintf("Check errored: %v", p)))
		}
	}()
	return newResult(c, c.Fn(s))
}

func newResult(c Check, o Outcome) Result {
	return Result{c.ID, c.Category, c.Title, c.Severity, o.Status, o.Detail, o.Fix}
}

// RunAll runs every check in order.
func RunAll(s *System) []Result {
	s.ResetCache()
	checks := AllChecks()
	results := make([]Result, 0, len(checks))
	for _, c := range checks {
		results = append(results, RunCheck(s, c))
	}
	return results
}

// Score is the weighted percentage: PASS earns full weight, WARN half, FAIL
// none; SKIP and INFO don't count.
func Score(results []Result) (int, string) {
	var total, earned float64
	for _, r := range results {
		if r.Status != Pass && r.Status != Warn && r.Status != Fail {
			continue
		}
		w := float64(r.Severity.Weight())
		total += w
		switch r.Status {
		case Pass:
			earned += w
		case Warn:
			earned += w / 2
		}
	}
	pct := 0
	if total > 0 {
		pct = int(math.RoundToEven(100 * earned / total))
	}
	switch {
	case pct >= 90:
		return pct, "A"
	case pct >= 80:
		return pct, "B"
	case pct >= 70:
		return pct, "C"
	case pct >= 60:
		return pct, "D"
	}
	return pct, "F"
}

// Counts tallies results by status.
func Counts(results []Result) map[Status]int {
	c := map[Status]int{}
	for _, r := range results {
		c[r.Status]++
	}
	return c
}
