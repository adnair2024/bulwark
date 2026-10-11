package audit

import (
	"fmt"
	"io/fs"
	"strings"
)

var fileChecks = []Check{
	{"FILE-01", "Files", "/etc/passwd has safe permissions", Medium, passwdPerms},
	{"FILE-02", "Files", "/etc/shadow is not readable by other users", High, shadowPerms},
	{"FILE-03", "Files", "No world-writable files in /etc", Medium, worldWritableEtc},
	{"FILE-04", "Files", "/tmp has the sticky bit set", Medium, tmpSticky},
}

const (
	permGroupWrite = 0o020
	permOtherWrite = 0o002
	permOtherAll   = 0o007
	permSticky     = 0o1000
)

func passwdPerms(s *System) Outcome {
	st, ok := s.Stat("/etc/passwd")
	if !ok {
		return skip("Could not stat /etc/passwd.")
	}
	if st.Perm&(permGroupWrite|permOtherWrite) != 0 {
		return fail(fmt.Sprintf("/etc/passwd is writable by group/others (%#o).", st.Perm&0o777),
			"Run: sudo chmod 644 /etc/passwd")
	}
	return pass(fmt.Sprintf("Mode %#o.", st.Perm&0o777))
}

func shadowPerms(s *System) Outcome {
	st, ok := s.Stat("/etc/shadow")
	if !ok {
		return skip("/etc/shadow not found.")
	}
	if st.Perm&(permOtherAll|permGroupWrite) != 0 {
		return fail(fmt.Sprintf("/etc/shadow mode is %#o; password hashes may be exposed.", st.Perm&0o777),
			"Run: sudo chmod 640 /etc/shadow (or 600 on Arch)")
	}
	return pass(fmt.Sprintf("Mode %#o.", st.Perm&0o777))
}

func worldWritableEtc(s *System) Outcome {
	if st, ok := s.Stat("/etc"); !ok || !st.IsDir {
		return skip("/etc not found.")
	}
	var found []string
	s.Walk("/etc", func(p string, fi fs.FileInfo) {
		m := fi.Mode()
		if m&fs.ModeSymlink != 0 {
			return
		}
		if m&0o002 != 0 && m&fs.ModeSticky == 0 {
			found = append(found, p)
		}
	})
	if len(found) == 0 {
		return pass("No world-writable files or directories in /etc.")
	}
	shown := strings.Join(found[:min(len(found), 10)], ", ")
	if len(found) > 10 {
		shown += fmt.Sprintf(" (+%d more)", len(found)-10)
	}
	return fail(fmt.Sprintf("%d world-writable path(s): %s", len(found), shown),
		"Remove world-write: sudo chmod o-w <path>")
}

func tmpSticky(s *System) Outcome {
	st, ok := s.Stat("/tmp")
	if !ok {
		return skip("/tmp not found.")
	}
	if st.Perm&permOtherWrite != 0 && st.Perm&permSticky == 0 {
		return fail("/tmp is world-writable without the sticky bit; users can delete each other's files.",
			"Run: sudo chmod 1777 /tmp")
	}
	return pass(fmt.Sprintf("Mode %#o.", st.Perm))
}
