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

func TestReverseDNSVerifierMissingPTRIsUnverifiedAndCached(t *testing.T) {
	resolver := &fakeDNSResolver{
		ptrErr: &net.DNSError{Err: "no such host", Name: "198.51.100.10", IsNotFound: true},
	}
	verifier := &reverseDNSVerifier{
		allowedSuffixes: []string{".googlebot.com"},
		resolver:        resolver,
		cache:           newReverseDNSCache(reverseDNSCacheMaxEntries, reverseDNSCacheTTL),
	}

	ip := net.ParseIP("198.51.100.10")
	for i := 0; i < 2; i++ {
		result, err := verifier.Verify(context.Background(), ip)
		if err != nil {
			t.Fatalf("Verify() error = %v, want nil for missing PTR", err)
		}
		if result.Verified {
			t.Fatalf("Verify() = %+v, want unverified", result)
		}
		if result.Reason != "reverse_dns_no_ptr" {
			t.Fatalf("Verify() reason = %q, want reverse_dns_no_ptr", result.Reason)
		}
	}

	if resolver.ptrLookups != 1 {
		t.Fatalf("PTR lookups = %d, want 1 (result should be cached)", resolver.ptrLookups)
	}
}

func TestReverseDNSVerifierResolverFailureReturnsError(t *testing.T) {
	resolver := &fakeDNSResolver{
		ptrErr: &net.DNSError{Err: "server misbehaving", IsTimeout: true},
	}
	verifier := &reverseDNSVerifier{
		allowedSuffixes: []string{".googlebot.com"},
		resolver:        resolver,
		cache:           newReverseDNSCache(reverseDNSCacheMaxEntries, reverseDNSCacheTTL),
	}

	ip := net.ParseIP("198.51.100.10")
	for i := 0; i < 2; i++ {
		if _, err := verifier.Verify(context.Background(), ip); err == nil {
			t.Fatalf("Verify() error = nil, want resolver error")
		}
	}

	if resolver.ptrLookups != 2 {
		t.Fatalf("PTR lookups = %d, want 2 (errors must not be cached)", resolver.ptrLookups)
	}
}

func TestReverseDNSVerifierForwardNotFoundIsUnverified(t *testing.T) {
	resolver := &fakeDNSResolver{
		ptr: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
		},
		forwardErr: &net.DNSError{Err: "no such host", IsNotFound: true},
	}
	verifier := &reverseDNSVerifier{
		allowedSuffixes: []string{".googlebot.com"},
		resolver:        resolver,
		cache:           newReverseDNSCache(reverseDNSCacheMaxEntries, reverseDNSCacheTTL),
	}

	result, err := verifier.Verify(context.Background(), net.ParseIP("66.249.66.1"))
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil for forward not-found", err)
	}
	if result.Verified {
		t.Fatalf("Verify() = %+v, want unverified", result)
	}
	if result.Reason != "reverse_dns_no_roundtrip_match" {
		t.Fatalf("Verify() reason = %q, want reverse_dns_no_roundtrip_match", result.Reason)
	}
}

type fakeDNSResolver struct {
	ptr            map[string][]string
	forward        map[string][]net.IPAddr
	ptrErr         error
	forwardErr     error
	ptrLookups     int
	forwardLookups int
}

func (r *fakeDNSResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	r.ptrLookups++
	if r.ptrErr != nil {
		return nil, r.ptrErr
	}
	return r.ptr[addr], nil
}

func (r *fakeDNSResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.forwardLookups++
	if r.forwardErr != nil {
		return nil, r.forwardErr
	}
	return r.forward[host], nil
}
