package docker

import (
	"bytes"
	"context"
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
		// read-write, deploy dir read-only.
		binds = append(binds,
			"/var/run/docker.sock:/var/run/docker.sock",
			"/etc/opencode:/etc/opencode",
			"/opt/openchamber:/opt/openchamber:ro",
		)
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

// Ready probes the container's /health until the managed OpenCode server
// reports ready (the UI answers HTTP 200 before OpenCode is usable, so the
// probe requires isOpenCodeReady=true) or the timeout elapses.
func (p *Provisioner) Ready(ctx context.Context, u *userprov.User) error {
	name := p.ContainerName(u.Username)
	addr := net.JoinHostPort(name, "3000")
	deadline := time.Now().Add(p.cfg.ReadyTimeout)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/health", nil)
		if err != nil {
			return err
		}
		resp, err := p.http.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if resp.StatusCode < 500 && bytes.Contains(body, []byte(`"isOpenCodeReady":true`)) {
				return nil
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
