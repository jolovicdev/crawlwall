package ratelimit

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/jolovicdev/crawlwall/internal/lru"
)

const (
	defaultMaxEntries = 16384
	defaultEntryTTL   = 10 * time.Minute
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

// evictIdle drops entries that have not been used within the TTL, then trims
// the least recently used ones. Without this, a high-cardinality key such as
// request.ip would grow the map without bound; see lru.Trim for why a batch is
// reclaimed. Callers must hold l.mu.
func (l *Limiter) evictIdle(now time.Time) {
	for key, entry := range l.entries {
		if now.Sub(entry.lastAccess) > l.ttl {
			delete(l.entries, key)
		}
	}

	lru.Trim(l.entries, l.maxEntries, func(entry limiterEntry) time.Time {
		return entry.lastAccess
	})
}
