package verify

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/jolovicdev/crawlwall/internal/config"
)

func TestIPRangesVerifierFailsClosedWhenExpiredRefreshFails(t *testing.T) {
	source, fail := newFlakyIPRangeSource(t)
	verifier := newIPRangesVerifier(config.VerifyConfig{
		Sources:     []string{source},
		Refresh:     "1ms",
		StaleAction: config.StaleActionFailClosed,
		MaxStale:    "1h",
	}, zap.NewNop())

	result, err := verifier.Verify(context.Background(), net.ParseIP("20.125.66.81"))
	if err != nil {
		t.Fatalf("first Verify() error = %v", err)
	}
	if !result.Verified || result.Reason != "ip_range_match" {
		t.Fatalf("first Verify() = %+v, want fresh match", result)
	}

	fail.Store(true)
	time.Sleep(10 * time.Millisecond)

	result, err = verifier.Verify(context.Background(), net.ParseIP("20.125.66.81"))
	if err == nil {
		t.Fatalf("expired Verify() error = nil, result = %+v", result)
	}
	if result.Reason != "ip_range_refresh_failed" {
		t.Fatalf("expired Verify() reason = %q, want ip_range_refresh_failed", result.Reason)
	}
}

func TestIPRangesVerifierCanUseBoundedStaleCache(t *testing.T) {
	source, fail := newFlakyIPRangeSource(t)
	verifier := newIPRangesVerifier(config.VerifyConfig{
		Sources:     []string{source},
		Refresh:     "1ms",
		StaleAction: config.StaleActionUseStale,
		MaxStale:    "1h",
	}, zap.NewNop())

	if _, err := verifier.Verify(context.Background(), net.ParseIP("20.125.66.81")); err != nil {
		t.Fatalf("first Verify() error = %v", err)
	}

	fail.Store(true)
	time.Sleep(10 * time.Millisecond)

	result, err := verifier.Verify(context.Background(), net.ParseIP("20.125.66.81"))
	if err != nil {
		t.Fatalf("stale Verify() error = %v", err)
	}
	if !result.Verified || result.Reason != "ip_range_match_stale" {
		t.Fatalf("stale Verify() = %+v, want stale match", result)
	}
}

func newFlakyIPRangeSource(t *testing.T) (string, *atomic.Bool) {
	t.Helper()
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "temporary range source failure", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"20.125.66.80/28"}]}`))
	}))
	t.Cleanup(server.Close)
	return server.URL, &fail
}
