package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/worqcompany/brain-worq/orchestrator/internal/auth"
	"github.com/worqcompany/brain-worq/orchestrator/internal/culler"
	"github.com/worqcompany/brain-worq/orchestrator/internal/docker"
	"github.com/worqcompany/brain-worq/orchestrator/internal/proxy"
	"github.com/worqcompany/brain-worq/orchestrator/internal/ready"
	"github.com/worqcompany/brain-worq/orchestrator/internal/userprov"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := loadConfig()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dockerClient, err := docker.New(ctx, cfg.DockerHost, docker.Config{
		Image:         cfg.Image,
		Network:       cfg.Network,
		MemoryLimitMB: cfg.MemoryLimitMB,
		CPUs:          cfg.CPUs,
		PidsLimit:     cfg.PidsLimit,
		ReadyTimeout:  cfg.ReadyTimeout,
		Env:           map[string]string{},
		AdminEmails:   cfg.AdminEmails,
		UIPassword:    cfg.UIPassword,
		JWTSecret:     cfg.JWTSecret,
		UserModels:    cfg.UserModels,
		AdminModels:   cfg.AdminModels,
	}, logger)
	if err != nil {
		logger.Error("docker client", "err", err)
		os.Exit(1)
	}

	users := userprov.New(cfg.UserBaseDir, logger)
	authz := auth.NewValidator(cfg.OAuth2ProxyURL, cfg.AllowedDomain, logger)
	hub := ready.NewHub()

	px := proxy.New(dockerClient, users, authz, hub, logger)
	cl := culler.New(dockerClient, users, hub, cfg.PauseIdle, cfg.StopIdle, logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/oauth2/auth", px.ForwardAuth)
	mux.HandleFunc("/ready", hub.HandleReady)
	mux.HandleFunc("/", px.Handle)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}

	go cl.Run(ctx)

	go func() {
		logger.Info("orchestrator listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
}
