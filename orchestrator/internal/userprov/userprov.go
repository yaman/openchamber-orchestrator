package userprov

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
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

	// Slow path: useradd on the host (orchestrator runs as root with host /etc).
	p.logger.Info("userprov: creating host user", "email", email, "username", username, "home", home)
	cmd := exec.Command("useradd",
		"--create-home",
		"--home-dir", home,
		"--shell", "/bin/bash",
		"--comment", email,
		username,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("useradd %s: %v: %s", username, err, strings.TrimSpace(string(out)))
	}

	if err := os.MkdirAll(home+"/.config/opencode", 0o700); err != nil {
		return nil, fmt.Errorf("mkdir config: %w", err)
	}
	if uid := lookupUID(username); uid > 0 {
		if err := os.Chown(home+"/.config/opencode", uid, uid); err != nil {
			p.logger.Warn("userprov: chown config", "err", err)
		}
	}

	uid := lookupUID(username)
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

var _ = time.Second // placeholder to keep imports tidy if unused
