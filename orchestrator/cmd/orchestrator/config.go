package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr string

	// Google OIDC session validation via oauth2-proxy.
	OAuth2ProxyURL string
	AllowedDomain  string

	// Docker
	DockerHost string
	Image      string
	Network    string

	// Real Linux users on the host VM.
	UserBaseDir string

	// Per-user container resources.
	MemoryLimitMB int64
	CPUs          float64
	PidsLimit     int64

	// Idle lifecycle
	PauseIdle time.Duration
	StopIdle  time.Duration

	// Readiness
	ReadyTimeout time.Duration

	// Admin
	AdminEmails map[string]bool

	// Shared per-user container auth (browser never sees it; the orchestrator
	// logs in server-side and injects the session cookie).
	UIPassword string
	JWTSecret  string
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func loadConfig() Config {
	adminEmails := map[string]bool{}
	for _, e := range strings.Split(env("ORCH_ADMIN_EMAILS", ""), ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			adminEmails[e] = true
		}
	}

	return Config{
		ListenAddr:     env("ORCH_LISTEN", ":8080"),
		OAuth2ProxyURL: env("ORCH_OAUTH2_PROXY_URL", "http://oauth2-proxy:4180"),
		AllowedDomain:  env("ORCH_ALLOWED_DOMAIN", "worqcompany.com"),
		DockerHost:     env("ORCH_DOCKER_HOST", "unix:///var/run/docker.sock"),
		Image:          env("ORCH_IMAGE", "openchamber:1.20.0"),
		Network:        env("ORCH_NETWORK", "openchamber_default"),
		UserBaseDir:    env("ORCH_USER_BASE_DIR", "/home"),

		MemoryLimitMB: envInt("ORCH_MEM_MB", 4096),
		CPUs:          envFloat("ORCH_CPU", 2.0),
		PidsLimit:     envInt("ORCH_PIDS_LIMIT", 512),

		PauseIdle:    envDuration("ORCH_IDLE_PAUSE", 30*time.Minute),
		StopIdle:     envDuration("ORCH_IDLE_STOP", 24*time.Hour),
		ReadyTimeout: envDuration("ORCH_READY_TIMEOUT", 5*time.Minute),

		AdminEmails: adminEmails,

		UIPassword: env("ORCH_UI_PASSWORD", ""),
		JWTSecret:  env("ORCH_JWT_SECRET", ""),
	}
}
