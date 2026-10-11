package audit

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CmdResult is the outcome of a query command.
type CmdResult struct {
	Code   int
	Stdout string
}

// Runner executes a command (argv, binary first). ok is false when the binary
// is not installed or the command could not be run.
type Runner func(cmd []string) (res CmdResult, ok bool)

// FileStat is the subset of stat(2) the checks need. Perm holds the unix
// permission bits including setuid, setgid, and sticky (mode & 0o7777).
type FileStat struct {
	Perm  uint32
	UID   uint32
	IsDir bool
}

// System is the only way checks touch the machine. Paths resolve under Root so
// tests can point the auditor at a fake filesystem.
type System struct {
	Root   string
	IsRoot bool
	Runner Runner

	mu       sync.Mutex
	sshDone  bool
	sshCache map[string]string
}

// NewSystem returns a System rooted at root. Commands only run against a live
// system ("/"); with any other root they report as not installed.
func NewSystem(root string) *System {
	s := &System{Root: root, IsRoot: os.Geteuid() == 0}
	if filepath.Clean(root) == "/" {
		s.Runner = execRunner
	}
	return s
}

func execRunner(cmd []string) (CmdResult, bool) {
	path, err := exec.LookPath(cmd[0])
	if err != nil {
		return CmdResult{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, cmd[1:]...).Output()
	if err == nil {
		return CmdResult{Stdout: string(out)}, true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && ctx.Err() == nil {
		return CmdResult{Code: exitErr.ExitCode(), Stdout: string(out)}, true
	}
	return CmdResult{}, false
}

// Path maps an absolute path to its location under Root.
func (s *System) Path(p string) string {
	return filepath.Join(s.Root, p)
}

// Read returns the file contents, or ok == false if it can't be read.
func (s *System) Read(p string) (string, bool) {
	b, err := os.ReadFile(s.Path(p))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// Stat follows symlinks, like stat(2).
func (s *System) Stat(p string) (FileStat, bool) {
	fi, err := os.Stat(s.Path(p))
	if err != nil {
		return FileStat{}, false
	}
	return statOf(fi), true
}

func (s *System) Exists(p string) bool {
	_, err := os.Stat(s.Path(p))
	return err == nil
}

// Glob expands pattern under Root and returns sorted paths relative to Root
// (with a leading slash).
func (s *System) Glob(pattern string) []string {
	matches, err := filepath.Glob(s.Path(pattern))
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, s.rel(m))
	}
	return out
}

// Walk visits every entry below dir (not dir itself) without following
// symlinks. fi describes the entry itself (lstat). Unreadable entries are
// skipped.
func (s *System) Walk(dir string, fn func(p string, fi fs.FileInfo)) {
	base, err := filepath.EvalSymlinks(s.Path(dir))
	if err != nil {
		return
	}
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == base {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			fn(filepath.Join(dir, strings.TrimPrefix(p, base)), fi)
		}
		return nil
	})
}

func (s *System) rel(p string) string {
	r, err := filepath.Rel(s.Root, p)
	if err != nil {
		return p
	}
	return "/" + filepath.ToSlash(r)
}

// Run executes a query command. ok is false if the binary isn't installed.
func (s *System) Run(cmd ...string) (CmdResult, bool) {
	if s.Runner == nil {
		return CmdResult{}, false
	}
	return s.Runner(cmd)
}

// Sysctl reads a kernel parameter such as "net.ipv4.ip_forward" from /proc/sys.
func (s *System) Sysctl(key string) (string, bool) {
	v, ok := s.Read("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	return strings.TrimSpace(v), ok
}

// OSRelease parses /etc/os-release into a map.
func (s *System) OSRelease() map[string]string {
	data := map[string]string{}
	text, _ := s.Read("/etc/os-release")
	for _, line := range strings.Split(text, "\n") {
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		data[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return data
}

// ResetCache drops per-run cached state (the effective SSH config).
func (s *System) ResetCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sshDone, s.sshCache = false, nil
}

func statOf(fi fs.FileInfo) FileStat {
	m := fi.Mode()
	perm := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		perm |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		perm |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		perm |= 0o1000
	}
	return FileStat{Perm: perm, UID: uidOf(fi), IsDir: fi.IsDir()}
}
