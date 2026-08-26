package userprov

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Username validation: POSIX-safe, lowercase, 1-31 chars.
var usernameRe = regexp.MustCompile(`^[a-z0-9_][a-z0-9_-]{0,31}$`)

// Provisioner creates and caches real Linux users on the host VM. The
// orchestrator container must run as root and mount /etc/passwd, /etc/shadow,
// /etc/group and the user base dir (/home) from the host.
//
// useradd(8) is NOT used: it rewrites /etc/passwd via rename(2), which fails
// on bind-mounted single files. Appending entries directly works on bind
// mounts and is exactly what useradd does under the hood.
type Provisioner struct {
	baseDir string
	logger  *slog.Logger
	mu      sync.Mutex
	cache   map[string]*User
}

type User struct {
	Username  string // posix username, e.g. "alice.yaman"
	Email     string // full login email, e.g. alice.yaman@worqcompany.com
	Home      string // /home/alice.yaman
	UID       int
	ConfigDir string // $HOME/.config/opencode — bound into the container
}

// sanitizeLocalPart maps an email local part to a POSIX username.
func sanitizeLocalPart(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return ""
	}
	local := strings.ToLower(email[:at])
	local = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, local)
	local = strings.Trim(local, "-_")
	if local == "" {
		return ""
	}
	if len(local) > 32 {
		local = local[:32]
	}
	return local
}

func New(baseDir string, logger *slog.Logger) *Provisioner {
	return &Provisioner{
		baseDir: baseDir,
		logger:  logger,
		cache:   map[string]*User{},
	}
}

// Get returns the real Linux user for an email, creating the account on the
// host if it does not exist yet (first successful login). Concurrency-safe.
func (p *Provisioner) Get(email string) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") {
		return nil, fmt.Errorf("invalid email: %q", email)
	}

	p.mu.Lock()
	if u, ok := p.cache[email]; ok {
		p.mu.Unlock()
		return u, nil
	}
	p.mu.Unlock()

	username := sanitizeLocalPart(email)
	if username == "" {
		return nil, fmt.Errorf("cannot derive username from %q", email)
	}
	if len(username) < 2 {
		username = username + "u"
	}

	// Re-check after unlock: another goroutine may have created it meanwhile.
	p.mu.Lock()
	defer p.mu.Unlock()
	if u, ok := p.cache[email]; ok {
		return u, nil
	}

	home := fmt.Sprintf("%s/%s", strings.TrimRight(p.baseDir, "/"), username)

	// Fast path: exists on the host already.
	if st, err := os.Stat(home); err == nil && st.IsDir() {
		uid := lookupUID(username)
		u := &User{Username: username, Email: email, Home: home, UID: uid, ConfigDir: home + "/.config/opencode"}
		p.cache[email] = u
		return u, nil
	}

	p.logger.Info("userprov: creating host user", "email", email, "username", username, "home", home)

	uid, err := nextUID()
	if err != nil {
		return nil, fmt.Errorf("next uid: %w", err)
	}
	gid := uid

	// Append entries to the bind-mounted host files. Append (O_APPEND) works
	// on bind mounts; useradd's rename-based rewrite does not.
	if err := appendLine("/etc/passwd", fmt.Sprintf("%s:x:%d:%d:%s:%s:/bin/bash", username, uid, gid, email, home)); err != nil {
		return nil, fmt.Errorf("append passwd: %w", err)
	}
	if err := appendLine("/etc/group", fmt.Sprintf("%s:x:%d:", username, gid)); err != nil {
		return nil, fmt.Errorf("append group: %w", err)
	}
	// Locked password (no shell login for these accounts; they exist so the
	// container can run as a real uid with a real home).
	if err := appendLine("/etc/shadow", fmt.Sprintf("%s:!:%d:0:99999:7:::", username, daysSinceEpoch())); err != nil {
		return nil, fmt.Errorf("append shadow: %w", err)
	}

	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir home: %w", err)
	}
	if err := os.MkdirAll(home+"/.config/opencode", 0o700); err != nil {
		return nil, fmt.Errorf("mkdir config: %w", err)
	}
	if err := os.Chown(home, uid, gid); err != nil {
		p.logger.Warn("userprov: chown home", "err", err)
	}
	if err := os.Chown(home+"/.config/opencode", uid, gid); err != nil {
		p.logger.Warn("userprov: chown config", "err", err)
	}

	u := &User{Username: username, Email: email, Home: home, UID: uid, ConfigDir: home + "/.config/opencode"}
	p.cache[email] = u
	p.logger.Info("userprov: user created", "username", username, "uid", uid)
	return u, nil
}

func (p *Provisioner) Lookup(username string) *User {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, u := range p.cache {
		if u.Username == username {
			return u
		}
	}
	return nil
}

// Range calls fn for every cached username (safe while holding the lock).
func (p *Provisioner) Range(fn func(username string)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, u := range p.cache {
		fn(u.Username)
	}
}

func lookupUID(username string) int {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return 0
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) >= 3 && fields[0] == username {
			var uid int
			fmt.Sscanf(fields[2], "%d", &uid)
			return uid
		}
	}
	return 0
}

// nextUID picks the next free uid >= 1000 (and gid) from /etc/passwd.
func nextUID() (int, error) {
	used := map[int]bool{}
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) >= 3 {
			var uid int
			if _, err := fmt.Sscanf(fields[2], "%d", &uid); err == nil {
				used[uid] = true
			}
		}
	}
	for uid := 1000; ; uid++ {
		if !used[uid] {
			return uid, nil
		}
	}
}

func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}
	return nil
}

func daysSinceEpoch() int {
	return int(time.Now().Unix() / 86400)
}
