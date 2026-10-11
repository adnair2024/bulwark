package audit

import (
	"fmt"
	"strconv"
	"strings"
)

// OpenSSH defaults for the keys the checks read.
var sshDefaults = map[string]string{
	"permitrootlogin":        "prohibit-password",
	"passwordauthentication": "yes",
	"permitemptypasswords":   "no",
	"x11forwarding":          "no",
	"maxauthtries":           "6",
}

const sshdConfigPath = "/etc/ssh/sshd_config"

// splitDirective splits "Key  value text" into the key and the rest of the line.
func splitDirective(line string) (key, value string) {
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.TrimSpace(line[i+1:])
}

// parseSSHConfig parses sshd_config the way sshd does: first value wins,
// Include is expanded in place, and parsing stops at the first Match block
// because everything after it is conditional. hitMatch reports whether a Match
// block ended the parse (in this file or an included one).
func parseSSHConfig(s *System, path string, seen map[string]bool) (cfg map[string]string, hitMatch bool) {
	cfg = map[string]string{}
	if seen[path] {
		return cfg, false
	}
	seen[path] = true
	text, ok := s.Read(path)
	if !ok {
		return cfg, false
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value := splitDirective(line)
		key = strings.ToLower(key)
		switch key {
		case "match":
			return cfg, true
		case "include":
			for _, pattern := range strings.Fields(value) {
				if !strings.HasPrefix(pattern, "/") {
					pattern = "/etc/ssh/" + pattern
				}
				for _, inc := range s.Glob(pattern) {
					sub, subMatch := parseSSHConfig(s, inc, seen)
					for k, v := range sub {
						if _, set := cfg[k]; !set {
							cfg[k] = v
						}
					}
					if subMatch {
						return cfg, true
					}
				}
			}
		default:
			if _, set := cfg[key]; !set {
				cfg[key] = strings.ToLower(value)
			}
		}
	}
	return cfg, false
}

// sshConfig returns the effective sshd settings, or ok == false if there is no
// SSH server configuration on the host. Results are cached per run.
func sshConfig(s *System) (map[string]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sshDone {
		s.sshCache = loadSSHConfig(s)
		s.sshDone = true
	}
	return s.sshCache, s.sshCache != nil
}

func loadSSHConfig(s *System) map[string]string {
	// `sshd -T` prints the real effective config, but it needs root.
	if s.IsRoot {
		if out, ok := s.Run("sshd", "-T"); ok && out.Code == 0 && strings.TrimSpace(out.Stdout) != "" {
			cfg := map[string]string{}
			for _, line := range strings.Split(out.Stdout, "\n") {
				key, value := splitDirective(strings.TrimSpace(line))
				if value == "" {
					continue
				}
				if _, set := cfg[strings.ToLower(key)]; !set {
					cfg[strings.ToLower(key)] = strings.ToLower(value)
				}
			}
			return cfg
		}
	}
	if !s.Exists(sshdConfigPath) {
		return nil
	}
	parsed, _ := parseSSHConfig(s, sshdConfigPath, map[string]bool{})
	cfg := map[string]string{}
	for k, v := range sshDefaults {
		cfg[k] = v
	}
	for k, v := range parsed {
		cfg[k] = v
	}
	return cfg
}

func cfgGet(cfg map[string]string, key, def string) string {
	if v, ok := cfg[key]; ok {
		return v
	}
	return def
}

func noSSH() Outcome {
	return skip("No SSH server configuration found.")
}

// withSSH wraps a check that needs the effective SSH config.
func withSSH(fn func(cfg map[string]string) Outcome) func(*System) Outcome {
	return func(s *System) Outcome {
		cfg, ok := sshConfig(s)
		if !ok {
			return noSSH()
		}
		return fn(cfg)
	}
}

var sshChecks = []Check{
	{"SSH-01", "SSH", "Root login over SSH is disabled", High, withSSH(sshRootLogin)},
	{"SSH-02", "SSH", "SSH password authentication is disabled", High, withSSH(sshPasswordAuth)},
	{"SSH-03", "SSH", "SSH does not allow empty passwords", High, withSSH(sshEmptyPasswords)},
	{"SSH-04", "SSH", "SSH limits authentication attempts", Low, withSSH(sshMaxAuthTries)},
	{"SSH-05", "SSH", "SSH X11 forwarding is disabled", Low, withSSH(sshX11)},
	{"SSH-06", "SSH", "sshd_config is not writable by non-root users", Medium, sshConfigPerms},
}

func sshRootLogin(cfg map[string]string) Outcome {
	v := cfgGet(cfg, "permitrootlogin", "prohibit-password")
	fix := "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd."
	switch v {
	case "no":
		return pass("PermitRootLogin is 'no'.")
	case "prohibit-password", "without-password", "forced-commands-only":
		return warn(fmt.Sprintf("PermitRootLogin is '%s': root can still log in with a key.", v), fix)
	}
	return fail(fmt.Sprintf("PermitRootLogin is '%s': root can log in with a password.", v), fix)
}

func sshPasswordAuth(cfg map[string]string) Outcome {
	if cfgGet(cfg, "passwordauthentication", "yes") == "no" {
		return pass("Only key-based authentication is allowed.")
	}
	return fail("Password logins are allowed, which exposes SSH to brute force.",
		"Set up SSH keys, then set 'PasswordAuthentication no' and restart sshd.")
}

func sshEmptyPasswords(cfg map[string]string) Outcome {
	if cfgGet(cfg, "permitemptypasswords", "no") == "no" {
		return pass("PermitEmptyPasswords is 'no'.")
	}
	return fail("Accounts with empty passwords can log in over SSH.",
		"Set 'PermitEmptyPasswords no' and restart sshd.")
}

func sshMaxAuthTries(cfg map[string]string) Outcome {
	n, err := strconv.Atoi(cfgGet(cfg, "maxauthtries", "6"))
	if err != nil {
		return warn("MaxAuthTries has an unreadable value.", "Set 'MaxAuthTries 4'.")
	}
	if n <= 4 {
		return pass(fmt.Sprintf("MaxAuthTries is %d.", n))
	}
	return warn(fmt.Sprintf("MaxAuthTries is %d; 4 or fewer is recommended.", n),
		"Set 'MaxAuthTries 4' in /etc/ssh/sshd_config.")
}

func sshX11(cfg map[string]string) Outcome {
	if cfgGet(cfg, "x11forwarding", "no") == "no" {
		return pass("X11Forwarding is 'no'.")
	}
	return warn("X11Forwarding is enabled.", "Set 'X11Forwarding no' unless you need remote GUI apps.")
}

func sshConfigPerms(s *System) Outcome {
	st, ok := s.Stat(sshdConfigPath)
	if !ok {
		return noSSH()
	}
	var problems []string
	if st.UID != 0 {
		problems = append(problems, "not owned by root")
	}
	if st.Perm&0o022 != 0 {
		problems = append(problems, "writable by group/others")
	}
	if len(problems) > 0 {
		return fail("sshd_config is "+strings.Join(problems, " and ")+".",
			"Run: sudo chown root:root /etc/ssh/sshd_config && sudo chmod 600 /etc/ssh/sshd_config")
	}
	return pass(fmt.Sprintf("Owned by root, mode %#o.", st.Perm&0o777))
}
