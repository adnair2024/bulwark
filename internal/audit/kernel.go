package audit

import (
	"fmt"
	"strings"
)

var kernelChecks = []Check{
	{"KRN-01", "Kernel", "Address space layout randomization is fully enabled", Medium, aslr},
	{"KRN-02", "Kernel", "IP forwarding is disabled", Low, ipForward},
	{"KRN-03", "Kernel", "TCP SYN cookies are enabled", Low, syncookies},
	{"KRN-04", "Kernel", "ICMP redirects are not accepted", Low, acceptRedirects},
	{"KRN-05", "Kernel", "ICMP redirects are not sent", Low, sendRedirects},
	{"KRN-06", "Kernel", "Kernel logs are restricted to root", Low, dmesgRestrict},
	{"KRN-07", "Kernel", "Kernel pointers are hidden", Low, kptrRestrict},
	{"KRN-08", "Kernel", "Symlink and hardlink protections are enabled", Medium, linkProtection},
}

const sysctlFixSuffix = " in /etc/sysctl.d/99-hardening.conf and run: sudo sysctl --system"

// sysctlCheck passes when ok(value) holds; otherwise it reports badStatus with
// the explanation why and a fix that sets the key to want.
func sysctlCheck(s *System, key string, ok func(string) bool, want string, badStatus Status, why string) Outcome {
	val, found := s.Sysctl(key)
	if !found {
		return skip(key + " not available.")
	}
	if ok(val) {
		return pass(fmt.Sprintf("%s = %s.", key, val))
	}
	return Outcome{
		Status: badStatus,
		Detail: strings.TrimSpace(fmt.Sprintf("%s = %s. %s", key, val, why)),
		Fix:    fmt.Sprintf("Add '%s = %s'", key, want) + sysctlFixSuffix,
	}
}

func equals(want string) func(string) bool {
	return func(v string) bool { return v == want }
}

func aslr(s *System) Outcome {
	return sysctlCheck(s, "kernel.randomize_va_space", equals("2"), "2", Fail,
		"ASLR makes memory-corruption exploits harder.")
}

func ipForward(s *System) Outcome {
	return sysctlCheck(s, "net.ipv4.ip_forward", equals("0"), "0", Warn,
		"Expected on routers and Docker/VM hosts; otherwise disable it.")
}

func syncookies(s *System) Outcome {
	return sysctlCheck(s, "net.ipv4.tcp_syncookies", equals("1"), "1", Fail,
		"Protects against SYN flood attacks.")
}

func acceptRedirects(s *System) Outcome {
	return sysctlCheck(s, "net.ipv4.conf.all.accept_redirects", equals("0"), "0", Warn,
		"Redirects can be used to reroute traffic through an attacker.")
}

func sendRedirects(s *System) Outcome {
	return sysctlCheck(s, "net.ipv4.conf.all.send_redirects", equals("0"), "0", Warn,
		"Only routers need to send redirects.")
}

func dmesgRestrict(s *System) Outcome {
	return sysctlCheck(s, "kernel.dmesg_restrict", equals("1"), "1", Warn,
		"dmesg can leak kernel addresses useful to exploits.")
}

func kptrRestrict(s *System) Outcome {
	return sysctlCheck(s, "kernel.kptr_restrict", func(v string) bool { return v == "1" || v == "2" }, "1", Warn,
		"Exposed kernel pointers help bypass ASLR.")
}

func linkProtection(s *System) Outcome {
	keys := []string{"fs.protected_symlinks", "fs.protected_hardlinks"}
	var bad []string
	available := false
	for _, k := range keys {
		v, ok := s.Sysctl(k)
		if !ok {
			continue
		}
		available = true
		if v != "1" {
			bad = append(bad, k)
		}
	}
	if !available {
		return skip("Link protection sysctls not available.")
	}
	if len(bad) > 0 {
		settings := make([]string, len(bad))
		for i, k := range bad {
			settings[i] = fmt.Sprintf("'%s = 1'", k)
		}
		return fail("Disabled: "+strings.Join(bad, ", ")+". These block common /tmp race attacks.",
			"Set "+strings.Join(settings, " and ")+sysctlFixSuffix)
	}
	return pass("fs.protected_symlinks and fs.protected_hardlinks are 1.")
}
