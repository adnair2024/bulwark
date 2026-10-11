package audit

import (
	"fmt"
	"strings"
)

var loggingChecks = []Check{
	{"LOG-01", "Logging", "System auditing (auditd) is running", Low, auditd},
	{"LOG-02", "Logging", "SSH brute-force protection is running", Medium, bruteforceProtection},
}

// serviceActive returns the first active service among names ("" if none is
// active). available is false when systemd can't be queried.
func serviceActive(s *System, names ...string) (active string, available bool) {
	answered := false
	for _, n := range names {
		out, ok := s.Run("systemctl", "is-active", n)
		if !ok {
			return "", false
		}
		switch state := strings.TrimSpace(out.Stdout); state {
		case "active":
			return n, true
		case "inactive", "failed", "activating", "unknown":
			answered = true
		}
	}
	return "", answered
}

func auditd(s *System) Outcome {
	active, ok := serviceActive(s, "auditd")
	if !ok {
		return skip("systemd not available.")
	}
	if active != "" {
		return pass("auditd is active.")
	}
	return warn("auditd is not running, so security events aren't recorded in detail.",
		"Install and enable auditd (Ubuntu: sudo apt install auditd; Arch: sudo pacman -S audit), "+
			"then: sudo systemctl enable --now auditd")
}

func bruteforceProtection(s *System) Outcome {
	if _, ok := sshConfig(s); !ok {
		return noSSH()
	}
	active, ok := serviceActive(s, "fail2ban", "sshguard", "crowdsec")
	if !ok {
		return skip("systemd not available.")
	}
	if active != "" {
		return pass(fmt.Sprintf("%s is active.", active))
	}
	return warn("No fail2ban, sshguard, or CrowdSec service is running.",
		"Install fail2ban and enable its sshd jail: sudo systemctl enable --now fail2ban")
}
