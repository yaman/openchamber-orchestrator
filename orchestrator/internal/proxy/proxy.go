package proxy

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/worqcompany/brain-worq/orchestrator/internal/auth"
	"github.com/worqcompany/brain-worq/orchestrator/internal/docker"
	"github.com/worqcompany/brain-worq/orchestrator/internal/ready"
	"github.com/worqcompany/brain-worq/orchestrator/internal/userprov"
)

// Handler is the traffic entry point behind Caddy.
//
// Two endpoints:
//   - /oauth2/auth — forward_auth target: validates the session cookie
//     against oauth2-proxy, wakes the user's container, and answers 200
//     with X-Auth-Request-Email (or 401 when unauthenticated).
//   - / — content proxy: reads the principal from X-Forwarded-User (set by
//     Caddy from the forward-auth response), routes to the per-user
//     container, or shows the "preparing your workspace" page.
type Handler struct {
	prov    *docker.Provisioner
	users   *userprov.Provisioner
	authz   *auth.Validator
	ready   *ready.Hub
	proxy   map[string]*httputil.ReverseProxy
	mu      sync.Mutex
	session map[string]sessionEntry // per-user openchamber UI session cache
	logger  *slog.Logger
	waiting *template.Template
}

type sessionEntry struct {
	token   string
	expires time.Time
}

func New(prov *docker.Provisioner, users *userprov.Provisioner, authz *auth.Validator, readyHub *ready.Hub, logger *slog.Logger) *Handler {
	h := &Handler{
		prov:    prov,
		users:   users,
		authz:   authz,
		ready:   readyHub,
		logger:  logger,
		proxy:   map[string]*httputil.ReverseProxy{},
		session: map[string]sessionEntry{},
	}
	h.waiting = template.Must(template.New("waiting").Parse(waitingPage))
	return h
}

// validate checks the browser session cookie against oauth2-proxy and returns
// the authenticated principal.
func (h *Handler) validate(ctx context.Context, r *http.Request) (auth.Principal, error) {
	return h.authz.Validate(ctx, r)
}

// ForwardAuth implements the Caddy forward_auth contract. It validates the
// session against oauth2-proxy, wakes (creates / unpauses) the user's
// container, and answers 200 with identity headers — or 401.
func (h *Handler) ForwardAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	principal, err := h.validate(ctx, r)
	if err != nil {
		h.logger.Error("proxy: forward-auth validation failed", "err", err)
		http.Error(w, "authentication service unavailable", http.StatusServiceUnavailable)
		return
	}
	if principal.Email == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	u, err := h.users.Get(principal.Email)
	if err != nil {
		h.logger.Error("proxy: user provisioning failed", "email", principal.Email, "err", err)
		http.Error(w, "could not provision account", http.StatusInternalServerError)
		return
	}

	// Wake now so the first content request is fast; idempotent when running.
	if _, err := h.prov.Ensure(ctx, u); err != nil {
		h.logger.Error("proxy: forward-auth ensure failed", "user", u.Username, "err", err)
		http.Error(w, "could not start workspace", http.StatusInternalServerError)
		return
	}

	// oauth2-proxy may have refreshed the session cookie (202); hand the new
	// cookie to the browser so the next request validates cleanly.
	for _, c := range principal.RefreshCookies {
		w.Header().Add("Set-Cookie", c)
	}

	w.Header().Set("X-Auth-Request-Email", principal.Email)
	w.Header().Set("X-Auth-Request-User", principal.Email)
	w.WriteHeader(http.StatusOK)
}

// Handle routes content traffic to the user's container.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Caddy only forwards content requests after a successful forward_auth,
	// so the principal header is present.
	email := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-User")))
	if email == "" || !strings.Contains(email, "@") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	u, err := h.users.Get(email)
	if err != nil {
		h.logger.Error("proxy: user provisioning failed", "email", email, "err", err)
		http.Error(w, "could not provision account", http.StatusInternalServerError)
		return
	}

	state, err := h.prov.Ensure(ctx, u)
	if err != nil {
		h.logger.Error("proxy: ensure failed", "user", u.Username, "err", err)
		http.Error(w, "could not start your workspace", http.StatusInternalServerError)
		return
	}

	readyCtx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	if err := h.prov.Ready(readyCtx, u); err != nil {
		if state == docker.StateAbsent {
			h.serveWaiting(w, r, u)
			return
		}
		h.logger.Error("proxy: container not ready", "user", u.Username, "err", err)
		http.Error(w, "workspace is taking too long to start", http.StatusGatewayTimeout)
		return
	}

	h.ready.Touch(u.Username)
	h.ensureSession(w, r, u)
	h.serveProxy(w, r, u)
}

// ensureSession makes sure the browser carries an oc_ui_session cookie valid
// for this user's container. The orchestrator performs the UI password login
// server-side and hands the cookie to the browser via Set-Cookie, so the
// user never sees openchamber's own login screen.
func (h *Handler) ensureSession(w http.ResponseWriter, r *http.Request, u *userprov.User) {
	if r.Header.Get("Cookie") != "" {
		// Browser already carries the session cookie (parse cheaply).
		for _, part := range strings.Split(r.Header.Get("Cookie"), ";") {
			if strings.HasPrefix(strings.TrimSpace(part), "oc_ui_session=") {
				return
			}
		}
	}

	h.mu.Lock()
	entry, ok := h.session[u.Username]
	h.mu.Unlock()
	token := ""
	if ok && time.Now().Before(entry.expires) {
		token = entry.token
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		var err error
		token, err = h.prov.Login(ctx, u)
		if err != nil {
			h.logger.Warn("proxy: silent login failed", "user", u.Username, "err", err)
			return // let the request through; container will show its login page
		}
		h.mu.Lock()
		h.session[u.Username] = sessionEntry{token: token, expires: time.Now().Add(time.Hour)}
		h.mu.Unlock()
	}

	// Attach to the upstream request and hand the cookie to the browser.
	existing := r.Header.Get("Cookie")
	if existing != "" {
		r.Header.Set("Cookie", existing+"; oc_ui_session="+token)
	} else {
		r.Header.Set("Cookie", "oc_ui_session="+token)
	}
	w.Header().Add("Set-Cookie", "oc_ui_session="+token+"; Path=/; Max-Age=43200; SameSite=Lax")
}

// probeWait bounds the synchronous readiness wait before showing the waiting
// page; the /ready poller keeps probing afterwards with the full timeout.
const probeWait = 5 * time.Second

// serveWaiting shows the spinner page and registers a readiness watcher so
// the page's /ready polls keep probing until the container answers.
func (h *Handler) serveWaiting(w http.ResponseWriter, r *http.Request, u *userprov.User) {
	h.logger.Info("proxy: workspace preparing", "user", u.Username)
	h.ready.Watch(u.Username, func() {
		// One short probe per poll; Ready only returns nil when the app
		// answers, so a single attempt per /ready request is enough.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := h.prov.Ready(ctx, u); err == nil {
			h.ready.MarkReady(u.Username)
		}
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.waiting.Execute(w, map[string]string{"User": u.Username}); err != nil {
		h.logger.Error("proxy: waiting template", "err", err)
	}
}

// serveProxy reverse-proxies all traffic (HTTP, WebSocket, SSE) to the
// per-user container over the shared docker network.
func (h *Handler) serveProxy(w http.ResponseWriter, r *http.Request, u *userprov.User) {
	upstream, _ := url.Parse("http://" + net.JoinHostPort("openchamber-"+u.Username, "3000"))
	rp := h.getProxy(upstream)
	rp.ServeHTTP(w, r)
}

func (h *Handler) getProxy(upstream *url.URL) *httputil.ReverseProxy {
	h.mu.Lock()
	defer h.mu.Unlock()
	if rp, ok := h.proxy[upstream.Host]; ok {
		return rp
	}
	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			return
		}
		h.logger.Warn("proxy: upstream error", "host", upstream.Host, "err", err)
		http.Error(w, "workspace unavailable", http.StatusBadGateway)
	}
	rp.Transport = &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	h.proxy[upstream.Host] = rp
	return rp
}

const waitingPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Preparing your workspace</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: dark; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0b0e14; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  .card { text-align: center; max-width: 420px; padding: 48px 32px; }
  .spinner {
    width: 44px; height: 44px; margin: 0 auto 24px; border-radius: 50%;
    border: 4px solid #2d333b; border-top-color: #4493f8; animation: spin 1s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  h1 { font-size: 20px; font-weight: 600; margin: 0 0 8px; }
  p  { font-size: 14px; color: #8b949e; margin: 0 0 20px; line-height: 1.5; }
  .stage { font-size: 13px; color: #58a6ff; font-variant-numeric: tabular-nums; }
  .bar { height: 4px; border-radius: 2px; background: #2d333b; overflow: hidden; margin-top: 24px; }
  .bar > i { display: block; height: 100%; width: 40%; border-radius: 2px; background: #4493f8; animation: slide 1.4s ease-in-out infinite; }
  @keyframes slide { 0% { transform: translateX(-110%); } 100% { transform: translateX(260%); } }
</style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <h1>Preparing your workspace</h1>
    <p>We are spinning up your OpenChamber instance on <code>{{.User}}</code>. First-time setups can take a minute; returning users are ready in seconds.</p>
    <div class="stage" id="stage">contacting your workspace&hellip;</div>
    <div class="bar"><i></i></div>
  </div>
  <script>
    const stages = ["starting container", "loading OpenChamber", "connecting OpenCode server", "almost ready"];
    let i = 0;
    setInterval(() => {
      document.getElementById("stage").textContent = stages[i++ % stages.length];
    }, 4000);
    async function poll() {
      try {
        const r = await fetch("/ready?u=" + encodeURIComponent({{.User}}), { cache: "no-store" });
        if (r.ok) { window.location.replace("/"); return; }
      } catch (e) {}
      setTimeout(poll, 1500);
    }
    poll();
  </script>
</body>
</html>`
