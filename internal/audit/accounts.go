package audit

import (
	"sort"
	"strings"
)

var accountChecks = []Check{
	{"ACC-01", "Accounts", "Only root has UID 0", High, uidZero},
	{"ACC-02", "Accounts", "No accounts have an empty password", High, emptyPasswords},
	{"ACC-03", "Accounts", "Administrative (sudo/wheel) users", Low, adminUsers},
}

// passwdEntries returns the well-formed (7-field) lines of /etc/passwd.
func passwdEntries(s *System) [][]string {
	text, _ := s.Read("/etc/passwd")
	var entries [][]string
	for _, line := range strings.Split(text, "\n") {
		if f := strings.Split(line, ":"); len(f) >= 7 {
			entries = append(entries, f)
		}
	}
	return entries
}

func uidZero(s *System) Outcome {
	entries := passwdEntries(s)
	if len(entries) == 0 {
		return skip("Could not read /etc/passwd.")
	}
	var extra []string
	for _, e := range entries {
		if e[2] == "0" && e[0] != "root" {
			extra = append(extra, e[0])
		}
	}
	if len(extra) > 0 {
		return fail("Other accounts have UID 0: "+strings.Join(extra, ", ")+".",
			"Give these accounts a unique non-zero UID or remove them.")
	}
	return pass("root is the only UID 0 account.")
}

func emptyPasswords(s *System) Outcome {
	text, ok := s.Read("/etc/shadow")
	if !ok {
		return needsRoot(s, "/etc/shadow")
	}
	var empty []string
	for _, line := range strings.Split(text, "\n") {
		if f := strings.Split(line, ":"); len(f) >= 2 && f[1] == "" {
			empty = append(empty, f[0])
		}
	}
	if len(empty) > 0 {
		return fail("Accounts with no password: "+strings.Join(empty, ", ")+".",
			"Set a password (passwd USER) or lock the account (passwd -l USER).")
	}
	return pass("Every account has a password or is locked.")
}

func adminUsers(s *System) Outcome {
	text, ok := s.Read("/etc/group")
	if !ok {
		return skip("Could not read /etc/group.")
	}
	set := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 || f[3] == "" || (f[0] != "sudo" && f[0] != "wheel" && f[0] != "admin") {
			continue
		}
		for _, u := range strings.Split(f[3], ",") {
			if u != "" {
				set[u] = true
			}
		}
	}
	if len(set) == 0 {
		return info("No members in sudo/wheel/admin groups.")
	}
	admins := make([]string, 0, len(set))
	for u := range set {
		admins = append(admins, u)
	}
	sort.Strings(admins)
	return info("Admin users: " + strings.Join(admins, ", ") + ". Confirm each one still needs admin rights.")
}
