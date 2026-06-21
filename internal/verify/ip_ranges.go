package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"github.com/jolovicdev/crawlwall/internal/config"
)

type ipRangesVerifier struct {
	sources     []string
	refresh     time.Duration
	staleAction string
	maxStale    time.Duration
	client      *http.Client
	logger      *zap.Logger
	cache       rangeCache
	fetchGroup  singleflight.Group
}

func newIPRangesVerifier(cfg config.VerifyConfig, logger *zap.Logger) Verifier {
	interval := 12 * time.Hour
	if cfg.Refresh != "" {
		if parsed, err := time.ParseDuration(cfg.Refresh); err == nil {
			interval = parsed
		}
	}

	maxStale := time.Duration(0)
	if cfg.MaxStale != "" {
		if parsed, err := time.ParseDuration(cfg.MaxStale); err == nil {
			maxStale = parsed
		}
	}

	staleAction := cfg.StaleAction
	if staleAction == "" {
		staleAction = config.StaleActionFailClosed
	}

	return &ipRangesVerifier{
		sources:     cfg.Sources,
		refresh:     interval,
		staleAction: staleAction,
		maxStale:    maxStale,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

func (v *ipRangesVerifier) Verify(ctx context.Context, ip net.IP) (Result, error) {
	networks, stale, err := v.loadNetworks(ctx)
	if err != nil {
		return Result{Type: "ip_ranges", Reason: "ip_range_refresh_failed"}, err
	}

	matchReason := "ip_range_match"
	noMatchReason := "ip_range_no_match"
	if stale {
		matchReason = "ip_range_match_stale"
		noMatchReason = "ip_range_no_match_stale"
	}

	for _, network := range networks {
		if network.Contains(ip) {
			return Result{
				Verified: true,
				Type:     "ip_ranges",
				Reason:   matchReason,
			}, nil
		}
	}

	return Result{
		Verified: false,
		Type:     "ip_ranges",
		Reason:   noMatchReason,
	}, nil
}

func (v *ipRangesVerifier) loadNetworks(ctx context.Context) ([]*net.IPNet, bool, error) {
	now := time.Now()
	if networks, ok := v.cache.get(now); ok {
		return networks, false, nil
	}

	networks, err := v.fetchAndStore(ctx)
	if err != nil {
		stale := v.cache.snapshot()
		if v.canUseStale(now, stale) {
			v.logger.Warn("crawlwall ip range refresh failed; using stale cache", zap.Error(err))
			return stale.networks, true, nil
		}
		return nil, false, err
	}
	return networks, false, nil
}

// fetchAndStore fetches the configured sources and updates the cache. Concurrent
// callers (request-path misses and the background refresher) share one fetch via
// singleflight instead of stampeding the sources.
func (v *ipRangesVerifier) fetchAndStore(ctx context.Context) ([]*net.IPNet, error) {
	result, err, _ := v.fetchGroup.Do("fetch", func() (any, error) {
		now := time.Now()
		networks, fetchErr := v.fetchNetworks(ctx)
		if fetchErr != nil {
			v.cache.setError(fetchErr)
			return nil, fetchErr
		}
		v.cache.set(networks, now, now.Add(v.refresh))
		return networks, nil
	})
	if err != nil {
		return nil, err
	}
	return result.([]*net.IPNet), nil
}

// forceRefresh fetches regardless of cache freshness. Used by the warm start
// and the background refresher.
func (v *ipRangesVerifier) forceRefresh(ctx context.Context) error {
	_, err := v.fetchAndStore(ctx)
	return err
}

// refreshInterval is slightly shorter than the cache lifetime so the background
// refresher keeps the cache warm and requests avoid the inline fetch path.
func (v *ipRangesVerifier) refreshInterval() time.Duration {
	if v.refresh <= 0 {
		return 12 * time.Hour
	}
	if interval := v.refresh - v.refresh/10; interval > 0 {
		return interval
	}
	return v.refresh
}

func (v *ipRangesVerifier) CacheStatus(ctx context.Context, status CacheStatus) CacheStatus {
	_, _, _ = v.loadNetworks(ctx)

	now := time.Now()
	snapshot := v.cache.snapshot()
	status.CIDRCount = len(snapshot.networks)
	status.LastFetch = snapshot.lastFetch
	status.ExpiresAt = snapshot.expiresAt
	if v.maxStale > 0 && !snapshot.expiresAt.IsZero() {
		status.StaleUntil = snapshot.expiresAt.Add(v.maxStale)
	}
	status.StaleAction = v.staleAction
	status.Error = snapshot.lastError

	switch {
	case status.CIDRCount > 0 && now.Before(status.ExpiresAt):
		status.State = "fresh"
	case status.CIDRCount > 0 && status.Error != "" && !v.canUseStale(now, snapshot):
		status.State = "error"
	case status.CIDRCount > 0:
		status.State = "stale"
	case status.Error != "":
		status.State = "error"
	default:
		status.State = "stale"
	}

	return status
}

func (v *ipRangesVerifier) canUseStale(now time.Time, snapshot cacheSnapshot) bool {
	if v.staleAction != config.StaleActionUseStale || v.maxStale <= 0 || len(snapshot.networks) == 0 {
		return false
	}
	return !now.After(snapshot.expiresAt.Add(v.maxStale))
}

func (v *ipRangesVerifier) fetchNetworks(ctx context.Context) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, source := range v.sources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}

		resp, err := v.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", source, err)
		}

		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", source, readErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("fetch %s: unexpected status %d", source, resp.StatusCode)
		}

		parsed, err := parseCIDRsFromJSON(body)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", source, err)
		}
		networks = append(networks, parsed...)
	}
	return networks, nil
}

func parseCIDRsFromJSON(data []byte) ([]*net.IPNet, error) {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}

	var cidrs []*net.IPNet
	collectCIDRs(value, &cidrs)
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("no CIDRs found in source document")
	}
	return cidrs, nil
}

func collectCIDRs(value any, cidrs *[]*net.IPNet) {
	switch typed := value.(type) {
	case map[string]any:
		for _, item := range typed {
			collectCIDRs(item, cidrs)
		}
	case []any:
		for _, item := range typed {
			collectCIDRs(item, cidrs)
		}
	case string:
		if network := parseNetworkString(typed); network != nil {
			*cidrs = append(*cidrs, network)
		}
	}
}

func parseNetworkString(value string) *net.IPNet {
	if _, network, err := net.ParseCIDR(value); err == nil {
		return network
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return nil
	}

	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(bits, bits),
	}
}

type noneVerifier struct{}

func (noneVerifier) Verify(context.Context, net.IP) (Result, error) {
	return Result{
		Verified: false,
		Type:     "none",
		Reason:   "verification_not_required",
	}, nil
}
