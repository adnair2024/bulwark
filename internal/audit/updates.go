package audit

import (
	"fmt"
	"strings"
)

var updateChecks = []Check{
	{"UPD-01", "Updates", "No pending package updates", High, pendingUpdates},
	{"UPD-02", "Updates", "Automatic security updates are enabled", Medium, autoUpdates},
}

// family maps os-release to debian, arch, redhat, or unknown.
func family(s *System) string {
	rel := s.OSRelease()
	ids := map[string]bool{rel["ID"]: true}
	for _, id := range strings.Fields(rel["ID_LIKE"]) {
		ids[id] = true
	}
	for _, f := range []struct {
		name string
		ids  []string
	}{
		{"debian", []string{"debian", "ubuntu"}},
		{"arch", []string{"arch"}},
		{"redhat", []string{"fedora", "rhel", "centos"}},
	} {
		for _, id := range f.ids {
			if ids[id] {
				return f.name
			}
		}
	}
	return "unknown"
}

func countLines(text string) int {
	n := 0
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

func pendingUpdates(s *System) Outcome {
	fam := family(s)
	fix := map[string]string{
		"debian": "Run: sudo apt update && sudo apt upgrade",
		"arch":   "Run: sudo pacman -Syu",
		"redhat": "Run: sudo dnf upgrade",
	}[fam]
	if fix == "" {
		fix = "Apply pending updates."
	}
	switch fam {
	case "debian":
		return debianUpdates(s, fix)
	case "arch":
		return archUpdates(s, fix)
	case "redhat":
		return redhatUpdates(s, fix)
	}
	return skip("Unrecognized distribution.")
}

func debianUpdates(s *System, fix string) Outcome {
	out, ok := s.Run("apt", "list", "--upgradable")
	if !ok {
		return skip("apt not available.")
	}
	var pkgs, security int
	for _, l := range strings.Split(out.Stdout, "\n") {
		if !strings.Contains(l, "/") || strings.HasPrefix(l, "Listing") {
			continue
		}
		pkgs++
		if strings.Contains(l, "-security") {
			security++
		}
	}
	const note = " (as of the last 'apt update')."
	switch {
	case security > 0:
		return fail(fmt.Sprintf("%d security update(s) pending, %d total%s", security, pkgs, note), fix)
	case pkgs > 0:
		return warn(fmt.Sprintf("%d update(s) pending, none flagged as security%s", pkgs, note), fix)
	}
	return pass("No pending updates" + note)
}

func archUpdates(s *System, fix string) Outcome {
	out, ok := s.Run("checkupdates")
	if !ok {
		return skip("checkupdates not found; install pacman-contrib for this check.")
	}
	switch out.Code {
	case 2:
		return pass("System is up to date.")
	case 0:
		return fail(fmt.Sprintf("%d package update(s) pending. Arch is rolling-release, so updates include security fixes.",
			countLines(out.Stdout)), fix)
	}
	return skip("checkupdates failed (no network?).")
}

func redhatUpdates(s *System, fix string) Outcome {
	out, ok := s.Run("dnf", "check-update", "-q")
	if !ok {
		return skip("dnf not available.")
	}
	switch out.Code {
	case 100:
		return warn(fmt.Sprintf("%d update(s) pending.", countLines(out.Stdout)), fix)
	case 0:
		return pass("System is up to date.")
	}
	return skip("dnf check-update failed.")
}

func autoUpdates(s *System) Outcome {
	if family(s) != "debian" {
		return skip("Only checked on Debian/Ubuntu (unattended-upgrades).")
	}
	var text strings.Builder
	for _, f := range s.Glob("/etc/apt/apt.conf.d/*") {
		if t, ok := s.Read(f); ok {
			text.WriteString(t)
		}
	}
	if strings.Contains(text.String(), `APT::Periodic::Unattended-Upgrade "1"`) {
		return pass("unattended-upgrades is enabled.")
	}
	return warn("Automatic security updates are not enabled.",
		"Run: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades")
}
