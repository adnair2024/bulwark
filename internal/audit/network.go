package audit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var networkChecks = []Check{
	{"NET-01", "Network", "A host firewall is active", High, firewall},
	{"NET-02", "Network", "No risky services exposed to the network", High, exposedServices},
}

// riskyPorts are services that should rarely be reachable from the network.
var riskyPorts = map[int]string{
	21: "FTP", 23: "Telnet", 69: "TFTP", 111: "rpcbind", 135: "MS-RPC",
	139: "NetBIOS", 445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh",
	2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
	5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
	27017: "MongoDB",
}

func firewall(s *System) Outcome {
	const fix = "Enable a firewall, e.g. on Ubuntu: sudo ufw default deny incoming && " +
		"sudo ufw allow ssh && sudo ufw enable"
	if out, ok := s.Run("ufw", "status"); ok && strings.Contains(out.Stdout, "Status: active") {
		return pass("ufw is active.")
	}
	if out, ok := s.Run("firewall-cmd", "--state"); ok && strings.TrimSpace(out.Stdout) == "running" {
		return pass("firewalld is running.")
	}
	if out, ok := s.Run("nft", "list", "ruleset"); ok && out.Code == 0 {
		if nftHasRules(out.Stdout) || strings.Contains(out.Stdout, "policy drop") {
			return pass("nftables has an active ruleset.")
		}
	}
	if out, ok := s.Run("iptables", "-S"); ok && out.Code == 0 {
		lines := strings.Split(out.Stdout, "\n")
		restrictive, hasInput := false, false
		for _, l := range lines {
			if strings.HasPrefix(l, "-P INPUT DROP") || strings.HasPrefix(l, "-P INPUT REJECT") {
				restrictive = true
			}
			if strings.HasPrefix(l, "-A INPUT") {
				hasInput = true
			}
		}
		if restrictive || hasInput {
			return pass("iptables has INPUT rules.")
		}
		return fail("iptables INPUT chain accepts everything and no other firewall is active.", fix)
	}
	if !s.IsRoot {
		return warn("Could not confirm an active firewall; run with sudo for an accurate result.", fix)
	}
	return fail("No active firewall found (checked ufw, firewalld, nftables, iptables).", fix)
}

// nftHasRules reports whether the ruleset has any line beyond table/chain
// scaffolding and accept policies.
func nftHasRules(ruleset string) bool {
	for _, l := range strings.Split(ruleset, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		scaffold := false
		for _, p := range []string{"table", "chain", "type", "}", "policy accept"} {
			if strings.HasPrefix(l, p) {
				scaffold = true
				break
			}
		}
		if !scaffold {
			return true
		}
	}
	return false
}

type listener struct {
	scope string // "all", "loopback", or "specific"
	port  int
}

// parseProcNet returns the LISTEN sockets in /proc/net/tcp[6].
func parseProcNet(text string, v6 bool) []listener {
	var out []listener
	lines := strings.Split(text, "\n")
	if len(lines) > 0 {
		lines = lines[1:] // header
	}
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != "0A" { // 0A = TCP_LISTEN
			continue
		}
		addr, portHex, found := strings.Cut(f[1], ":")
		if !found {
			continue
		}
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil {
			continue
		}
		scope := "specific"
		switch {
		case strings.Trim(addr, "0") == "":
			scope = "all"
		case !v6 && strings.HasSuffix(addr, "7F"),
			v6 && addr == "00000000000000000000000001000000":
			scope = "loopback"
		}
		out = append(out, listener{scope, int(port)})
	}
	return out
}

func exposedServices(s *System) Outcome {
	var sockets []listener
	found := false
	for _, src := range []struct {
		path string
		v6   bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		if text, ok := s.Read(src.path); ok {
			found = true
			sockets = append(sockets, parseProcNet(text, src.v6)...)
		}
	}
	if !found {
		return skip("Could not read /proc/net/tcp.")
	}
	seen := map[int]bool{}
	var exposed []int
	for _, l := range sockets {
		if l.scope != "loopback" && !seen[l.port] {
			seen[l.port] = true
			exposed = append(exposed, l.port)
		}
	}
	sort.Ints(exposed)
	var risky, all []string
	for _, p := range exposed {
		all = append(all, strconv.Itoa(p))
		if name, ok := riskyPorts[p]; ok {
			risky = append(risky, fmt.Sprintf("%d (%s)", p, name))
		}
	}
	listing := "none"
	if len(all) > 0 {
		listing = strings.Join(all, ", ")
	}
	if len(risky) > 0 {
		return fail(fmt.Sprintf("Risky services listening on the network: %s. All exposed TCP ports: %s.",
			strings.Join(risky, ", "), listing),
			"Bind these services to 127.0.0.1, firewall them, or disable them if unused.")
	}
	return pass(fmt.Sprintf("Network-exposed TCP ports: %s. Confirm each is expected.", listing))
}
