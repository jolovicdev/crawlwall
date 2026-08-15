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

	"github.com/jolovicdev/crawlwall/v2/internal/config"
	"github.com/jolovicdev/crawlwall/v2/internal/version"
)

const (
	// maxSourceBytes caps how much of a range document is read. Sources are
	// third-party URLs; an unbounded io.ReadAll would let one of them exhaust
	// memory.
	maxSourceBytes = 8 << 20

	// fetchBackoff throttles request-path refetches after a failure. Without
	// it an unreachable source costs every single request a full client
	// timeout and hammers the source. The background refresher is unaffected
	// and keeps retrying on its own interval.
	fetchBackoff = 30 * time.Second

	// A source that publishes a wildcard prefix such as 0.0.0.0/0 would verify
	// every client as the bot. Crawler operators publish far narrower blocks,
	// so anything this broad is treated as corrupt and dropped. The bar is set
	// low enough that no plausible real publication trips it.
	minIPv4PrefixBits = 8
	minIPv6PrefixBits = 16
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

	// A recent fetch already failed. Serve stale if policy allows it, otherwise
	// fail fast rather than making every request wait on the same dead source.
	if snapshot := v.cache.snapshot(); now.Before(snapshot.retryAfter) {
		if v.canUseStale(now, snapshot) {
			return snapshot.networks, true, nil
		}
		return nil, false, fmt.Errorf("ip range refresh failed: %s", snapshot.lastError)
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
			v.cache.setError(fetchErr, now.Add(fetchBackoff))
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
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "crawlwall/"+version.Version)

		resp, err := v.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", source, err)
		}

		// Check the status before reading: there is no reason to pull megabytes
		// off a 500 page.
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("fetch %s: unexpected status %d", source, resp.StatusCode)
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes+1))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", source, readErr)
		}
		if len(body) > maxSourceBytes {
			return nil, fmt.Errorf("read %s: document exceeds %d bytes", source, maxSourceBytes)
		}

		parsed, rejected, err := parseCIDRsFromJSON(body)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", source, err)
		}
		if rejected > 0 {
			v.logger.Warn("crawlwall ip range source published overly broad prefixes",
				zap.String("source", source),
				zap.Int("rejected", rejected),
			)
		}
		networks = append(networks, parsed...)
	}
	return networks, nil
}

// parseCIDRsFromJSON walks an arbitrary JSON document and collects every string
// that parses as a CIDR or bare IP, which covers the shapes the major crawler
// operators publish without hard-coding each one. It also reports how many
// entries were dropped for being too broad to be a credible bot range.
func parseCIDRsFromJSON(data []byte) ([]*net.IPNet, int, error) {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, 0, err
	}

	var cidrs []*net.IPNet
	rejected := 0
	collectCIDRs(value, &cidrs, &rejected)
	if len(cidrs) == 0 {
		return nil, rejected, fmt.Errorf("no usable CIDRs found in source document")
	}
	return cidrs, rejected, nil
}

func collectCIDRs(value any, cidrs *[]*net.IPNet, rejected *int) {
	switch typed := value.(type) {
	case map[string]any:
		for _, item := range typed {
			collectCIDRs(item, cidrs, rejected)
		}
	case []any:
		for _, item := range typed {
			collectCIDRs(item, cidrs, rejected)
		}
	case string:
		network := parseNetworkString(typed)
		switch {
		case network == nil:
		case !credibleNetwork(network):
			*rejected++
		default:
			*cidrs = append(*cidrs, network)
		}
	}
}

// credibleNetwork rejects prefixes broad enough that accepting them would
// verify most of the internet as the bot, such as 0.0.0.0/0.
func credibleNetwork(network *net.IPNet) bool {
	ones, bits := network.Mask.Size()
	switch bits {
	case 0:
		return false // non-contiguous mask
	case 32:
		return ones >= minIPv4PrefixBits
	default:
		return ones >= minIPv6PrefixBits
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
