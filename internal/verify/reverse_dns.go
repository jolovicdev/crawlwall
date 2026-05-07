package verify

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	reverseDNSCacheTTL        = 5 * time.Minute
	reverseDNSCacheMaxEntries = 4096
)

type dnsResolver interface {
	LookupAddr(context.Context, string) ([]string, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type reverseDNSVerifier struct {
	allowedSuffixes []string
	resolver        dnsResolver
	cache           *reverseDNSCache
}

func newReverseDNSVerifier(allowedSuffixes []string) Verifier {
	return &reverseDNSVerifier{
		allowedSuffixes: allowedSuffixes,
		resolver:        net.DefaultResolver,
		cache:           newReverseDNSCache(reverseDNSCacheMaxEntries, reverseDNSCacheTTL),
	}
}

func (v *reverseDNSVerifier) Verify(ctx context.Context, ip net.IP) (Result, error) {
	key := ip.String()
	if result, ok := v.cache.get(key); ok {
		return result, nil
	}

	result, err := v.lookup(ctx, ip)
	if err != nil {
		return result, err
	}
	v.cache.set(key, result)
	return result, nil
}

func (v *reverseDNSVerifier) lookup(ctx context.Context, ip net.IP) (Result, error) {
	names, err := v.resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return Result{Type: "reverse_dns", Reason: "ptr_lookup_failed"}, err
	}

	for _, name := range names {
		host := strings.TrimSuffix(strings.ToLower(name), ".")
		if !v.allowed(host) {
			continue
		}

		addrs, err := v.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return Result{Type: "reverse_dns", Reason: "forward_lookup_failed"}, err
		}
		for _, addr := range addrs {
			if addr.IP.Equal(ip) {
				return Result{
					Verified: true,
					Type:     "reverse_dns",
					Reason:   "reverse_dns_match",
				}, nil
			}
		}
	}

	return Result{
		Verified: false,
		Type:     "reverse_dns",
		Reason:   "reverse_dns_no_roundtrip_match",
	}, nil
}

func (v *reverseDNSVerifier) allowed(host string) bool {
	for _, suffix := range v.allowedSuffixes {
		normalized := strings.TrimPrefix(strings.ToLower(suffix), ".")
		if host == normalized || strings.HasSuffix(host, "."+normalized) {
			return true
		}
	}
	return false
}

type reverseDNSCache struct {
	mu         sync.Mutex
	maxEntries int
	ttl        time.Duration
	items      map[string]reverseDNSCacheEntry
}

type reverseDNSCacheEntry struct {
	result     Result
	expiresAt  time.Time
	lastAccess time.Time
}

func newReverseDNSCache(maxEntries int, ttl time.Duration) *reverseDNSCache {
	return &reverseDNSCache{
		maxEntries: maxEntries,
		ttl:        ttl,
		items:      map[string]reverseDNSCacheEntry{},
	}
}

func (c *reverseDNSCache) get(key string) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.items[key]
	if !ok {
		return Result{}, false
	}

	now := time.Now()
	if now.After(entry.expiresAt) {
		delete(c.items, key)
		return Result{}, false
	}

	entry.lastAccess = now
	c.items[key] = entry
	return entry.result, true
}

func (c *reverseDNSCache) set(key string, result Result) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.items[key] = reverseDNSCacheEntry{
		result:     result,
		expiresAt:  now.Add(c.ttl),
		lastAccess: now,
	}

	if len(c.items) > c.maxEntries {
		c.evictOldest()
	}
}

func (c *reverseDNSCache) evictOldest() {
	var oldestKey string
	var oldestAccess time.Time
	for key, entry := range c.items {
		if oldestKey == "" || entry.lastAccess.Before(oldestAccess) {
			oldestKey = key
			oldestAccess = entry.lastAccess
		}
	}
	if oldestKey != "" {
		delete(c.items, oldestKey)
	}
}
