package verify

import (
	"net"
	"sync"
	"time"
)

type rangeCache struct {
	mu         sync.RWMutex
	networks   []*net.IPNet
	expiresAt  time.Time
	lastFetch  time.Time
	lastError  string
	retryAfter time.Time
}

// get returns the cached networks without copying them. Every set installs a
// freshly built slice that is never mutated afterwards, so the returned slice
// is safe to read concurrently; copying it here would allocate one slice per
// request.
func (c *rangeCache) get(now time.Time) ([]*net.IPNet, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.networks) == 0 || now.After(c.expiresAt) {
		return nil, false
	}
	return c.networks, true
}

func (c *rangeCache) snapshot() cacheSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cacheSnapshot{
		networks:   c.networks,
		expiresAt:  c.expiresAt,
		lastFetch:  c.lastFetch,
		lastError:  c.lastError,
		retryAfter: c.retryAfter,
	}
}

func (c *rangeCache) set(networks []*net.IPNet, lastFetch, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.networks = append([]*net.IPNet(nil), networks...)
	c.lastFetch = lastFetch
	c.expiresAt = expiresAt
	c.lastError = ""
	c.retryAfter = time.Time{}
}

// setError records why the last fetch failed and until when the request path
// should stop retrying it.
func (c *rangeCache) setError(err error, retryAfter time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastError = ""
		c.retryAfter = time.Time{}
		return
	}
	c.lastError = err.Error()
	c.retryAfter = retryAfter
}

type cacheSnapshot struct {
	networks   []*net.IPNet
	expiresAt  time.Time
	lastFetch  time.Time
	lastError  string
	retryAfter time.Time
}
