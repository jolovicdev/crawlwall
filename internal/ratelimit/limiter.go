package ratelimit

import (
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultMaxEntries = 16384
	defaultEntryTTL   = 10 * time.Minute

	// evictBatchDivisor sets how much headroom one eviction pass reclaims:
	// maxEntries/evictBatchDivisor entries, so the scan cost amortizes over
	// that many subsequent inserts.
	evictBatchDivisor = 8
)

type limiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

type Limiter struct {
	mu         sync.Mutex
	entries    map[string]limiterEntry
	maxEntries int
	ttl        time.Duration
}

func New() *Limiter {
	return &Limiter{
		entries:    make(map[string]limiterEntry),
		maxEntries: defaultMaxEntries,
		ttl:        defaultEntryTTL,
	}
}

func (l *Limiter) Allow(key string, rpm int) bool {
	return l.allowAt(key, rpm, time.Now())
}

// allowAt is Allow with an explicit clock so the limit boundary and entry
// eviction can be tested without depending on wall-clock timing.
func (l *Limiter) allowAt(key string, rpm int, now time.Time) bool {
	if rpm <= 0 {
		return true
	}

	if strings.TrimSpace(key) == "" {
		key = "global"
	}

	l.mu.Lock()
	entry, ok := l.entries[key]
	if !ok {
		interval := time.Minute / time.Duration(rpm)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		entry = limiterEntry{limiter: rate.NewLimiter(rate.Every(interval), rpm)}
	}
	entry.lastAccess = now
	l.entries[key] = entry
	if len(l.entries) > l.maxEntries {
		l.evictIdle(now)
	}
	limiter := entry.limiter
	l.mu.Unlock()

	return limiter.AllowN(now, 1)
}

// evictIdle drops entries that have not been used within the TTL, then evicts
// the least recently used entries until the map is back under its low-water
// mark. Without this, a high-cardinality key such as request.ip would grow the
// map without bound.
//
// Eviction is batched rather than trimming a single entry per insert: a flood
// of unique keys keeps the map permanently at its cap, and evicting one at a
// time would make every request past the cap pay a full scan while holding the
// lock. Callers must hold l.mu.
func (l *Limiter) evictIdle(now time.Time) {
	for key, entry := range l.entries {
		if now.Sub(entry.lastAccess) > l.ttl {
			delete(l.entries, key)
		}
	}

	target := l.maxEntries - l.maxEntries/evictBatchDivisor
	surplus := len(l.entries) - target
	if surplus <= 0 {
		return
	}

	access := make([]time.Time, 0, len(l.entries))
	for _, entry := range l.entries {
		access = append(access, entry.lastAccess)
	}
	slices.SortFunc(access, func(a, b time.Time) int { return a.Compare(b) })

	cutoff := access[surplus-1]
	for key, entry := range l.entries {
		if !entry.lastAccess.After(cutoff) {
			delete(l.entries, key)
		}
	}
}
