package verify

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/jolovicdev/crawlwall/internal/config"
)

// A source that publishes a wildcard prefix would verify every client on earth
// as the bot, so those entries are dropped rather than trusted.
func TestParseCIDRsRejectsWildcardPrefixes(t *testing.T) {
	networks, rejected, err := parseCIDRsFromJSON([]byte(`{"prefixes":[
		{"ipv4Prefix":"0.0.0.0/0"},
		{"ipv6Prefix":"::/0"},
		{"ipv4Prefix":"20.125.66.80/28"}
	]}`))
	if err != nil {
		t.Fatalf("parseCIDRsFromJSON() error = %v", err)
	}
	if rejected != 2 {
		t.Fatalf("rejected = %d, want 2", rejected)
	}
	if len(networks) != 1 || networks[0].String() != "20.125.66.80/28" {
		t.Fatalf("networks = %v, want only the credible prefix", networks)
	}
}

func TestParseCIDRsFailsWhenEveryPrefixIsWildcard(t *testing.T) {
	if _, _, err := parseCIDRsFromJSON([]byte(`{"prefixes":[{"ipv4Prefix":"0.0.0.0/0"}]}`)); err == nil {
		t.Fatalf("parseCIDRsFromJSON() error = nil, want a failure rather than an empty allowlist")
	}
}

// An oversized document must fail rather than be read into memory: sources are
// third-party URLs.
func TestFetchNetworksRejectsOversizedDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":["`))
		chunk := strings.Repeat("a", 64<<10)
		for written := 0; written < maxSourceBytes+(1<<20); written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	verifier := newIPRangesVerifier(config.VerifyConfig{Sources: []string{server.URL}}, zap.NewNop()).(*ipRangesVerifier)

	_, err := verifier.fetchNetworks(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("fetchNetworks() error = %v, want a size limit error", err)
	}
}

// Once a fetch fails, the request path must not retry it per request: an
// unreachable source would otherwise cost every request a full client timeout.
func TestVerifyBacksOffAfterFetchFailure(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer server.Close()

	verifier := newIPRangesVerifier(config.VerifyConfig{
		Sources: []string{server.URL},
		Refresh: "1h",
	}, zap.NewNop())

	ip := net.ParseIP("20.0.0.5")
	for i := 0; i < 5; i++ {
		if _, err := verifier.Verify(context.Background(), ip); err == nil {
			t.Fatalf("Verify() error = nil, want the failed refresh to surface")
		}
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("source fetched %d times, want 1 (later attempts should be backed off)", got)
	}
}

// A burst from one IP must collapse into one lookup. Without this, a crawler
// flood opens one resolver query per request.
func TestReverseDNSSingleflightsConcurrentLookups(t *testing.T) {
	resolver := &slowResolver{}
	verifier := newTestReverseDNSVerifier(resolver, ".googlebot.com")

	ip := net.ParseIP("66.249.66.1")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := verifier.Verify(context.Background(), ip)
			if err != nil || !result.Verified {
				t.Errorf("Verify() = %+v, err = %v", result, err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&resolver.calls); got != 1 {
		t.Fatalf("PTR lookups = %d, want 1 (singleflight should dedupe)", got)
	}
}

type slowResolver struct {
	calls int32
}

func (r *slowResolver) LookupAddr(_ context.Context, _ string) ([]string, error) {
	atomic.AddInt32(&r.calls, 1)
	time.Sleep(100 * time.Millisecond)
	return []string{"crawl-66-249-66-1.googlebot.com."}, nil
}

func (r *slowResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("66.249.66.1")}}, nil
}
