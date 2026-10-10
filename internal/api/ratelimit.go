package api

import (
	"sync"
	"time"
)

// loginGuard rate-limits failed login attempts per client IP and per email and
// implements a simple brute-force lockout. It is deliberately small and
// in-memory; a multi-instance deployment should back it with a shared store.
type loginGuard struct {
	mu      sync.Mutex
	maxHits int
	window  time.Duration
	hits    map[string][]time.Time
}

func newLoginGuard(maxHits int, window time.Duration) *loginGuard {
	return &loginGuard{maxHits: maxHits, window: window, hits: map[string][]time.Time{}}
}

// allow records an attempt for key and reports whether it is within the limit.
func (g *loginGuard) allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-g.window)

	g.mu.Lock()
	defer g.mu.Unlock()

	log := g.hits[key]
	kept := log[:0]
	for _, t := range log {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= g.maxHits {
		g.hits[key] = kept
		return false
	}
	g.hits[key] = append(kept, now)

	if len(g.hits) > 10_000 {
		purgeBefore := now.Add(-2 * g.window)
		for k, log := range g.hits {
			if len(log) == 0 || log[len(log)-1].Before(purgeBefore) {
				delete(g.hits, k)
			}
		}
	}
	return true
}

// reset clears the attempt history for key (used on successful login).
func (g *loginGuard) reset(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.hits, key)
}
