package culler

import (
	"context"
	"log/slog"
	"time"

	"github.com/worqcompany/brain-worq/orchestrator/internal/docker"
	"github.com/worqcompany/brain-worq/orchestrator/internal/ready"
	"github.com/worqcompany/brain-worq/orchestrator/internal/userprov"
)

// Culler implements two-tier idle lifecycle:
//   - Pause after PauseIdle of no activity (instant resume, memory held)
//   - Stop after StopIdle (reclaims memory; cold start on next login)
type Culler struct {
	prov      *docker.Provisioner
	users     *userprov.Provisioner
	ready     *ready.Hub
	pauseIdle time.Duration
	stopIdle  time.Duration
	logger    *slog.Logger
}

func New(prov *docker.Provisioner, users *userprov.Provisioner, ready *ready.Hub, pauseIdle, stopIdle time.Duration, logger *slog.Logger) *Culler {
	return &Culler{
		prov:      prov,
		users:     users,
		ready:     ready,
		pauseIdle: pauseIdle,
		stopIdle:  stopIdle,
		logger:    logger,
	}
}

// Run polls every minute for users with activity history and parks idle
// containers. It never touches containers it does not know about.
func (c *Culler) Run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.poll(ctx)
		}
	}
}

func (c *Culler) poll(ctx context.Context) {
	// Tracked usernames come from activity touches and provisioned users.
	seen := map[string]bool{}
	c.users.Range(func(username string) {
		seen[username] = true
	})

	for username := range seen {
		last := c.ready.LastActivity(username)
		if last.IsZero() {
			continue // never seen active; leave alone
		}
		age := time.Since(last)
		switch {
		case age >= c.stopIdle:
			if err := c.prov.Stop(ctx, username); err != nil {
				c.logger.Warn("culler: stop failed", "user", username, "err", err)
				continue
			}
			c.logger.Info("culler: stopped (idle > stopIdle)", "user", username, "idle", age.Round(time.Minute))
		case age >= c.pauseIdle:
			paused, err := c.prov.IsPaused(ctx, username)
			if err != nil || paused {
				continue
			}
			if err := c.prov.Pause(ctx, username); err != nil {
				c.logger.Warn("culler: pause failed", "user", username, "err", err)
				continue
			}
			c.logger.Info("culler: paused (idle > pauseIdle)", "user", username, "idle", age.Round(time.Minute))
		}
	}
}
