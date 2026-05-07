package verify

import (
	"context"
	"net"
	"testing"
)

func TestReverseDNSVerifierCachesResultsByIP(t *testing.T) {
	resolver := &fakeDNSResolver{
		ptr: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
		},
		forward: map[string][]net.IPAddr{
			"crawl-66-249-66-1.googlebot.com": {{IP: net.ParseIP("66.249.66.1")}},
		},
	}
	verifier := &reverseDNSVerifier{
		allowedSuffixes: []string{".googlebot.com"},
		resolver:        resolver,
		cache:           newReverseDNSCache(reverseDNSCacheMaxEntries, reverseDNSCacheTTL),
	}

	ip := net.ParseIP("66.249.66.1")
	for i := 0; i < 2; i++ {
		result, err := verifier.Verify(context.Background(), ip)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if !result.Verified {
			t.Fatalf("Verify() = %+v, want verified", result)
		}
	}

	if resolver.ptrLookups != 1 {
		t.Fatalf("PTR lookups = %d, want 1", resolver.ptrLookups)
	}
	if resolver.forwardLookups != 1 {
		t.Fatalf("forward lookups = %d, want 1", resolver.forwardLookups)
	}
}

type fakeDNSResolver struct {
	ptr            map[string][]string
	forward        map[string][]net.IPAddr
	ptrLookups     int
	forwardLookups int
}

func (r *fakeDNSResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	r.ptrLookups++
	return r.ptr[addr], nil
}

func (r *fakeDNSResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.forwardLookups++
	return r.forward[host], nil
}
