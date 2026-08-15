package verify

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/jolovicdev/crawlwall/internal/lru"
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
	// allowedSuffixes is normalized at construction: lowercased with any
	// leading dot stripped, so the request path only compares bytes.
	allowedSuffixes []string
	resolver        dnsResolver
	cache           *reverseDNSCache
	lookupGroup     singleflight.Group
}

func newReverseDNSVerifier(allowedSuffixes []string) Verifier {
	normalized := make([]string, 0, len(allowedSuffixes))
	for _, suffix := range allowedSuffixes {
		if suffix = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(suffix)), "."); suffix != "" {
			normalized = append(normalized, suffix)
		}
	}

	return &reverseDNSVerifier{
		allowedSuffixes: normalized,
		resolver:        net.DefaultResolver,
		cache:           newReverseDNSCache(reverseDNSCacheMaxEntries, reverseDNSCacheTTL),
	}
}

func (v *reverseDNSVerifier) Verify(ctx context.Context, ip net.IP) (Result, error) {
	key := ip.String()
	if result, ok := v.cache.get(key); ok {
		return result, nil
	}

	// Requests from one IP arrive in bursts, and a resolver round trip is slow
	// relative to a request. Share one in-flight lookup per IP instead of
	// opening a query per request.
	out, err, _ := v.lookupGroup.Do(key, func() (any, error) {
		result, lookupErr := v.lookup(ctx, ip)
		if lookupErr == nil {
			v.cache.set(key, result)
		}
		return result, lookupErr
	})

	result, _ := out.(Result)
	return result, err
}

func (v *reverseDNSVerifier) lookup(ctx context.Context, ip net.IP) (Result, error) {
	names, err := v.resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		// An IP with no PTR record is the common case (most spoofers, many
		// clients). That is "not verified", not a verifier outage, so callers
		// can let policy decide instead of failing the verifier.
		if isNotFoundDNSError(err) {
			return Result{Type: "reverse_dns", Reason: "reverse_dns_no_ptr"}, nil
		}
		return Result{Type: "reverse_dns", Reason: "ptr_lookup_failed"}, err
	}

	for _, name := range names {
		host := strings.TrimSuffix(strings.ToLower(name), ".")
		if !v.allowed(host) {
			continue
		}

		addrs, err := v.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			if isNotFoundDNSError(err) {
				continue
			}
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

func isNotFoundDNSError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// allowed reports whether host is the allowed suffix itself or a label beneath
// it. The dot boundary matters: a plain HasSuffix would let evilgooglebot.com
// pass as .googlebot.com.
func (v *reverseDNSVerifier) allowed(host string) bool {
	for _, suffix := range v.allowedSuffixes {
		if host == suffix {
			return true
		}
		if len(host) > len(suffix) && host[len(host)-len(suffix)-1] == '.' && strings.HasSuffix(host, suffix) {
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
		c.evict(now)
	}
}

// evict drops expired entries, then trims the least recently used ones. A
// crawler flood from many spoofed IPs holds the cache at its cap; see lru.Trim.
func (c *reverseDNSCache) evict(now time.Time) {
	for key, entry := range c.items {
		if now.After(entry.expiresAt) {
			delete(c.items, key)
		}
	}

	lru.Trim(c.items, c.maxEntries, func(entry reverseDNSCacheEntry) time.Time {
		return entry.lastAccess
	})
}
