package ready

import (
	"net/http"
	"sync"
	"time"
)

// Hub tracks per-user container readiness and last-activity timestamps.
// The waiting page polls /ready; the culler reads activity through the same
// structure so "actively waiting" never counts as idle.
type Hub struct {
	mu      sync.Mutex
	ready   map[string]bool
	tokens  map[string]time.Time
	watches map[string]func()
}

func NewHub() *Hub {
	return &Hub{
		ready:   map[string]bool{},
		tokens:  map[string]time.Time{},
		watches: map[string]func(){},
	}
}

// MarkReady records that the container for username answered its health probe.
func (h *Hub) MarkReady(username string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ready[username] = true
}

// Watch registers a callback that will mark the user ready; used by the
// waiting page's readiness loop.
func (h *Hub) Watch(username string, check func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.watches[username] = check
}

// Touch records activity for the idle culler.
func (h *Hub) Touch(username string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tokens[username] = time.Now()
}

// LastActivity returns when the user was last seen active (zero if never).
func (h *Hub) LastActivity(username string) time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tokens[username]
}

// HandleReady answers the waiting page's poll: 200 once the container is up,
// 202 while still preparing.
func (h *Hub) HandleReady(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("u")
	if username == "" {
		http.Error(w, "missing u", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	if check, ok := h.watches[username]; ok {
		go check() // runs the readiness probe; marks ready via MarkReady
	}
	ready := h.ready[username]
	h.mu.Unlock()

	if ready {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte("preparing"))
}
