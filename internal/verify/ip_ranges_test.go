package verify

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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

func TestIPRangesVerifierSingleflightsConcurrentFetches(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"20.0.0.0/24"}]}`))
	}))
	defer server.Close()

	verifier := newIPRangesVerifier(config.VerifyConfig{
		Sources: []string{server.URL},
		Refresh: "1h",
	}, zap.NewNop()).(*ipRangesVerifier)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := verifier.Verify(context.Background(), net.ParseIP("20.0.0.5")); err != nil {
				t.Errorf("Verify() error = %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("source fetched %d times, want 1 (singleflight should dedupe)", got)
	}
}

func TestServiceBackgroundRefreshUpdatesCache(t *testing.T) {
	var payload atomic.Value
	payload.Store(`{"prefixes":[{"ipv4Prefix":"20.0.0.0/24"}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload.Load().(string)))
	}))
	defer server.Close()

	svc := NewService([]config.BotConfig{{
		ID:    "gptbot",
		Name:  "GPTBot",
		Class: "ai_training",
		Verify: config.VerifyConfig{
			Type:    "ip_ranges",
			Sources: []string{server.URL},
			Refresh: "60ms",
		},
	}}, zap.NewNop())
	svc.Start(context.Background())
	defer svc.Stop()

	result, err := svc.verifiers["gptbot"].Verify(context.Background(), net.ParseIP("20.0.0.5"))
	if err != nil || !result.Verified {
		t.Fatalf("warm start Verify() = %+v, err = %v", result, err)
	}

	payload.Store(`{"prefixes":[{"ipv4Prefix":"30.0.0.0/24"}]}`)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if res, _ := svc.verifiers["gptbot"].Verify(context.Background(), net.ParseIP("30.0.0.5")); res.Verified {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("background refresh did not pick up the rotated range")
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
