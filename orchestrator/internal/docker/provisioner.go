package docker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/worqcompany/brain-worq/orchestrator/internal/userprov"
	"golang.org/x/crypto/ssh"
)

// Provisioner drives per-user openchamber containers via the docker SDK.
// Only the orchestrator touches docker; users' containers are addressed by
// name on the shared network, never by host port.
type Provisioner struct {
	cli    *client.Client
	cfg    Config
	logger *slog.Logger
	http   *http.Client
	// per-user mutexes serialize create/start transitions so parallel
	// forward-auth requests for the same user cannot race (docker rejects
	// duplicate container names).
	locks sync.Map
	// per-user flag set once a boot was verified with a populated provider
	// list; Ready fast-paths on health alone afterwards.
	providersVerified sync.Map
}

type Config struct {
	Image         string
	Network       string
	MemoryLimitMB int64
	CPUs          float64
	PidsLimit     int64
	ReadyTimeout  time.Duration
	Env           map[string]string
	AdminEmails   map[string]bool
	// UI password + JWT secret shared by all per-user containers. The
	// orchestrator performs the /auth/session login itself and injects the
	// session cookie into proxied traffic, so the browser never sees a
	// login screen. Values come from the orchestrator's own env.
	UIPassword string
	JWTSecret  string

	// Model access: whitelists written into each user's
	// ~/.config/opencode/opencode.json. opencode intersects whitelists
	// across config layers (/etc/opencode shared + per-user), so the shared
	// config must NOT carry one (it would cap admins too); instead each
	// user's own config declares its set.
	UserModels  []string
	AdminModels []string
}

func New(ctx context.Context, host string, cfg Config, logger *slog.Logger) (*Provisioner, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithHost(host), client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	if _, err := cli.Ping(ctx); err != nil {
		return nil, fmt.Errorf("docker ping: %w", err)
	}
	return &Provisioner{
		cli:    cli,
		cfg:    cfg,
		logger: logger,
		http:   &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func (p *Provisioner) ContainerName(username string) string {
	return "openchamber-" + username
}

// ContainerState is the docker lifecycle state.
type ContainerState int

const (
	StateAbsent ContainerState = iota
	StatePaused
	StateStopped
	StateRunning
)

func (s ContainerState) String() string {
	switch s {
	case StateAbsent:
		return "absent"
	case StatePaused:
		return "paused"
	case StateStopped:
		return "stopped"
	case StateRunning:
		return "running"
	}
	return "unknown"
}

func (p *Provisioner) state(ctx context.Context, name string) (ContainerState, error) {
	insp, err := p.cli.ContainerInspect(ctx, name)
	if err != nil {
		if client.IsErrNotFound(err) {
			return StateAbsent, nil
		}
		return StateAbsent, err
	}
	if insp.State.Paused {
		return StatePaused, nil
	}
	if insp.State.Running {
		return StateRunning, nil
	}
	return StateStopped, nil
}

// Ensure returns the container to the running state: creates it on first
// login, unpauses it when paused, starts it when stopped. Serialized per
// user so parallel requests cannot race create/start.
func (p *Provisioner) Ensure(ctx context.Context, u *userprov.User) (ContainerState, error) {
	lock := p.userLock(u.Username)
	lock.Lock()
	defer lock.Unlock()

	name := p.ContainerName(u.Username)
	st, err := p.state(ctx, name)
	if err != nil {
		return st, err
	}
	switch st {
	case StateRunning:
		return st, nil
	case StatePaused:
		p.logger.Info("docker: unpausing", "container", name)
		if err := p.cli.ContainerUnpause(ctx, name); err != nil {
			return st, fmt.Errorf("unpause %s: %w", name, err)
		}
		return StateRunning, nil
	case StateStopped:
		p.logger.Info("docker: starting", "container", name)
		if err := p.cli.ContainerStart(ctx, name, container.StartOptions{}); err != nil {
			return st, fmt.Errorf("start %s: %w", name, err)
		}
		return StateRunning, nil
	case StateAbsent:
		return st, p.create(ctx, u, name)
	}
	return st, nil
}

// writeModelWhitelist writes (or merges into) the user's per-user
// ~/.config/opencode/opencode.json with an opencode-go whitelist. opencode
// intersects whitelists across config layers, so this per-user file is the
// only place a restriction can live without capping admins (the shared
// /etc/opencode config must stay whitelist-free).
func (p *Provisioner) writeModelWhitelist(u *userprov.User) error {
	models := p.cfg.UserModels
	if p.cfg.AdminEmails[strings.ToLower(strings.TrimSpace(u.Email))] && len(p.cfg.AdminModels) > 0 {
		models = p.cfg.AdminModels
	}
	if len(models) == 0 {
		return nil // no restriction configured
	}

	path := u.Home + "/.config/opencode/opencode.json"
	doc := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &doc) // best effort: preserve any existing keys
	}
	prov, _ := doc["provider"].(map[string]any)
	if prov == nil {
		prov = map[string]any{}
	}
	og, _ := prov["opencode-go"].(map[string]any)
	if og == nil {
		og = map[string]any{}
	}
	og["whitelist"] = models
	prov["opencode-go"] = og
	doc["provider"] = prov

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	_ = os.Chown(path, u.UID, u.UID)
	p.logger.Info("docker: wrote model whitelist", "user", u.Username, "models", len(models))
	return nil
}

// setupAdminSSH generates an ed25519 keypair in the admin's home and
// appends the public key to the VM root's authorized_keys, giving the admin
// container passwordless root access to the host (docker CLI, systemd,
// /opt/brain-worq). Runs once; idempotent on re-provision.
func (p *Provisioner) setupAdminSSH(u *userprov.User) error {
	keyPath := u.Home + "/.ssh/id_ed25519"
	if _, err := os.Stat(keyPath); err == nil {
		return nil // already provisioned
	}

	pubRaw, privRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privBlock, err := ssh.MarshalPrivateKey(privRaw, "")
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(privBlock)
	pubSSH, err := ssh.NewPublicKey(pubRaw)
	if err != nil {
		return err
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubSSH)))

	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath+".pub", []byte(pubLine+"\n"), 0o644); err != nil {
		return err
	}
	_ = os.Chown(keyPath, u.UID, u.UID)
	_ = os.Chown(keyPath+".pub", u.UID, u.UID)

	// Authorize root@host (the orchestrator runs as root, /root/.ssh exists).
	authPath := "/root/.ssh/authorized_keys"
	if err := os.MkdirAll("/root/.ssh", 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(authPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(pubLine + " " + u.Username + "@brain\n"); err != nil {
		return err
	}
	p.logger.Info("docker: admin ssh key provisioned", "user", u.Username)
	return nil
}

// writeAdminAgentsMD writes a per-user AGENTS.md with operational context for
// administering the brain.worq.company stack. Sits in the admin's own config
// dir (shared /etc/opencode stays generic).
const adminAgents = `# brain.worq.company admin operations

## Stack layout (VM: openchamber-vm, 34.10.110.155, us-central1-a, project worq-ai)

- Stack dir: /opt/brain-worq (git clone of yaman/openchamber-orchestrator; .env holds secrets, root-only)
- Services (docker compose): caddy (TLS+landing+/oauth2/*), oauth2-proxy (Google OIDC, --set-xauthrequest=true), orchestrator (Go: forward-auth, per-user container lifecycle, reverse proxy)
- Per-user containers: openchamber-<username> on openchamber_default net; image openchamber:1.20.0 (built once on VM from upstream at /opt/openchamber-src/src, patched)
- Deploy: push to main of yaman/openchamber-orchestrator; systemd timer och-deploy.timer (3 min) runs och-deploy.service = git fetch/reset + deploy.sh (docker compose build orchestrator + up -d --remove-orphans). Force: sudo systemctl start och-deploy.service
- openchamber image is NOT rebuilt by deploys; rebuild manually with sudo /opt/brain-worq/build-openchamber.sh (applies patches/openchamber-fix.patch)

## SSH from this container to the VM host

This container holds the admin SSH key (~/.ssh/id_ed25519, authorized on the host as root). Use:
  ssh -o StrictHostKeyChecking=accept-new root@172.18.0.1  (docker bridge gateway)

## Model access

- Per-user opencode whitelists are written by the orchestrator to ~/.config/opencode/opencode.json on the host
- Shared /etc/opencode/opencode.json must NOT carry a whitelist (opencode intersects across layers)

## Useful

- Watch services: sudo docker ps; logs: sudo docker logs orchestrator --tail 100
- Idle lifecycle: containers pause @30m, stop @24h (culler in orchestrator)
`

func (p *Provisioner) writeAdminAgentsMD(u *userprov.User) error {
	path := u.Home + "/.config/opencode/AGENTS.md"
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.WriteFile(path, []byte(adminAgents), 0o644); err != nil {
		return err
	}
	_ = os.Chown(path, u.UID, u.UID)
	return nil
}

func (p *Provisioner) userLock(username string) *sync.Mutex {
	actual, _ := p.locks.LoadOrStore(username, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

func (p *Provisioner) create(ctx context.Context, u *userprov.User, name string) error {
	p.logger.Info("docker: creating container", "container", name, "image", p.cfg.Image)

	// Bind-mount sources must exist on the host before the container starts.
	for _, dir := range []string{
		u.Home + "/.config/opencode",
		u.Home + "/.config/openchamber",
		u.Home + "/.local/share/opencode",
		u.Home + "/.local/state/opencode",
		u.Home + "/.ssh",
		u.Home + "/workspaces",
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		if err := os.Chown(dir, u.UID, u.UID); err != nil {
			p.logger.Warn("docker: chown state dir", "dir", dir, "err", err)
		}
	}

	if err := p.writeModelWhitelist(u); err != nil {
		return fmt.Errorf("model whitelist: %w", err)
	}

	binds := []string{
		// Per-user state dirs from the real home on the VM, bound at the
		// image's natural paths. The image's app lives at /home/openchamber,
		// so only these subdirs are overlaid — nothing is shadowed and the
		// entrypoint's hardcoded paths work as-is.
		u.Home + "/.config/opencode:/home/openchamber/.config/opencode",
		u.Home + "/.config/openchamber:/home/openchamber/.config/openchamber",
		u.Home + "/.local/share/opencode:/home/openchamber/.local/share/opencode",
		u.Home + "/.local/state/opencode:/home/openchamber/.local/state/opencode",
		u.Home + "/.ssh:/home/openchamber/.ssh",
		u.Home + "/workspaces:/home/openchamber/workspaces",
	}
	isAdmin := p.cfg.AdminEmails[strings.ToLower(strings.TrimSpace(u.Email))]
	if isAdmin {
		// Admin container: docker.sock for managing the stack, shared config
		// read-write, deploy dir read-only. Host passwd/group so tools (ssh)
		// resolve the container's numeric uid.
		binds = append(binds,
			"/var/run/docker.sock:/var/run/docker.sock",
			"/etc/opencode:/etc/opencode",
			"/opt/openchamber:/opt/openchamber:ro",
			"/etc/passwd:/etc/passwd:ro",
			"/etc/group:/etc/group:ro",
		)
		if err := p.setupAdminSSH(u); err != nil {
			p.logger.Warn("docker: admin ssh setup failed", "user", u.Username, "err", err)
		}
		if err := p.writeAdminAgentsMD(u); err != nil {
			p.logger.Warn("docker: admin AGENTS.md", "user", u.Username, "err", err)
		}
	} else {
		// Admin-managed shared opencode config (read-only for regular users).
		binds = append(binds, "/etc/opencode:/etc/opencode:ro")
	}

	resp, err := p.cli.ContainerCreate(ctx, &container.Config{
		Image: p.cfg.Image,
		User:  fmt.Sprintf("%d:%d", u.UID, u.UID),
		Env: append([]string{
			"HOME=/home/openchamber",
			"OPENCHAMBER_UI_PASSWORD=" + p.cfg.UIPassword,
			"OPENCODE_JWT_SECRET=" + p.cfg.JWTSecret,
			"OPENCHAMBER_HOST=0.0.0.0",
		}, envSlice(p.cfg.Env)...),
	}, &container.HostConfig{
		NetworkMode: container.NetworkMode(p.cfg.Network),
		Resources: container.Resources{
			Memory:    p.cfg.MemoryLimitMB * 1024 * 1024,
			NanoCPUs:  int64(p.cfg.CPUs * 1e9),
			PidsLimit: &p.cfg.PidsLimit,
		},
		Binds:         binds,
		RestartPolicy: container.RestartPolicy{Name: "unless-stopped"},
	}, nil, nil, name)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}

	if err := p.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	return nil
}

// Ready probes the container until the model picker would work: /health must
// report isOpenCodeReady=true AND /api/config/providers (behind the shared UI
// session) must list at least one provider. Both answer 200 before that — the
// app boots its HTTP layer and the opencode subprocess in stages — so without
// the providers check the browser lands in a chat whose model list is still
// empty and needs a manual reload. The login only needs to succeed once and is
// kept short so the per-poll cost is one cheap request.
func (p *Provisioner) Ready(ctx context.Context, u *userprov.User) error {
	name := p.ContainerName(u.Username)
	addr := net.JoinHostPort(name, "3000")
	healthURL := "http://" + addr + "/health"
	providersURL := "http://" + addr + "/api/config/providers"
	deadline := time.Now().Add(p.cfg.ReadyTimeout)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			return err
		}
		resp, err := p.http.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if resp.StatusCode < 500 && bytes.Contains(body, []byte(`"isOpenCodeReady":true`)) {
				if _, ok := p.providersVerified.Load(u.Username); ok {
					return nil
				}
				if p.providersListed(ctx, providersURL, u) {
					p.providersVerified.Store(u.Username, true)
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("container %s not ready within %s", name, p.cfg.ReadyTimeout)
}

// providersListed logs into the UI (shared password) and checks that the
// model-provider list is populated, mirroring what the chat's model picker
// needs on first paint.
func (p *Provisioner) providersListed(ctx context.Context, providersURL string, u *userprov.User) bool {
	token, err := p.Login(ctx, u)
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, providersURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Cookie", "oc_ui_session="+token)
	resp, err := p.http.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return false
	}
	// {"providers":[{...},...],...} — a non-empty array is the signal the
	// picker has options; keep it tolerant of any extra fields upstream adds.
	idx := bytes.Index(body, []byte(`"providers":[`))
	if idx < 0 {
		return false
	}
	return bytes.IndexByte(body[idx+len(`"providers":[`):], ']') > 0
}

// Login performs the UI password session login inside the container and
// returns the session cookie value for the user's browser session. The
// cookie is injected into every proxied response so the browser is
// transparently authenticated against its own container.
func (p *Provisioner) Login(ctx context.Context, u *userprov.User) (string, error) {
	name := p.ContainerName(u.Username)
	addr := net.JoinHostPort(name, "3000")
	body := fmt.Sprintf(`{"password":%q}`, p.cfg.UIPassword)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/auth/session", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("login %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login %s: status %d", name, resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "oc_ui_session" {
			return c.Value, nil
		}
	}
	return "", fmt.Errorf("login %s: no session cookie", name)
}

// Pause and Stop are used by the idle culler.
func (p *Provisioner) Pause(ctx context.Context, username string) error {
	return p.cli.ContainerPause(ctx, p.ContainerName(username))
}

func (p *Provisioner) Stop(ctx context.Context, username string) error {
	return p.cli.ContainerStop(ctx, p.ContainerName(username), container.StopOptions{Timeout: &twoSeconds})
}

var twoSeconds = 2

func (p *Provisioner) IsPaused(ctx context.Context, username string) (bool, error) {
	st, err := p.state(ctx, p.ContainerName(username))
	return st == StatePaused, err
}

func envSlice(m map[string]string) []string {
	out := []string{}
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}
