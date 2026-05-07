package verify

import (
	"net"
	"sync"
	"time"
)

type rangeCache struct {
	mu        sync.RWMutex
	networks  []*net.IPNet
	expiresAt time.Time
	lastFetch time.Time
	lastError string
}

func (c *rangeCache) get(now time.Time) ([]*net.IPNet, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.networks) == 0 || now.After(c.expiresAt) {
		return nil, false
	}
	return append([]*net.IPNet(nil), c.networks...), true
}

func (c *rangeCache) snapshot() cacheSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cacheSnapshot{
		networks:  append([]*net.IPNet(nil), c.networks...),
		expiresAt: c.expiresAt,
		lastFetch: c.lastFetch,
		lastError: c.lastError,
	}
}

func (c *rangeCache) set(networks []*net.IPNet, lastFetch, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.networks = append([]*net.IPNet(nil), networks...)
	c.lastFetch = lastFetch
	c.expiresAt = expiresAt
	c.lastError = ""
}

func (c *rangeCache) setError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.lastError = ""
		return
	}
	c.lastError = err.Error()
}

type cacheSnapshot struct {
	networks  []*net.IPNet
	expiresAt time.Time
	lastFetch time.Time
	lastError string
}
