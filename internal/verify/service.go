package verify

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/jolovicdev/crawlwall/internal/bot"
	"github.com/jolovicdev/crawlwall/internal/config"
)

type Input struct {
	Bot      bot.Identified
	RemoteIP net.IP
	Headers  http.Header
}

type Result struct {
	Verified bool
	Type     string
	Reason   string
}

type Verifier interface {
	Verify(context.Context, net.IP) (Result, error)
}

type CacheStatus struct {
	BotID       string    `json:"bot_id"`
	BotName     string    `json:"bot_name"`
	Type        string    `json:"type"`
	State       string    `json:"state"`
	CIDRCount   int       `json:"cidr_count"`
	LastFetch   time.Time `json:"last_fetch,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	StaleUntil  time.Time `json:"stale_until,omitempty"`
	StaleAction string    `json:"stale_action,omitempty"`
	Sources     []string  `json:"sources,omitempty"`
	Error       string    `json:"error,omitempty"`
}

type Service struct {
	logger    *zap.Logger
	verifiers map[string]Verifier
}

func NewService(bots []config.BotConfig, logger *zap.Logger) *Service {
	if logger == nil {
		logger = zap.NewNop()
	}

	verifiers := make(map[string]Verifier, len(bots))
	for _, cfg := range bots {
		switch cfg.Verify.Type {
		case "reverse_dns":
			verifiers[cfg.ID] = newReverseDNSVerifier(cfg.Verify.AllowedSuffixes)
		case "ip_ranges":
			verifiers[cfg.ID] = newIPRangesVerifier(cfg.Verify, logger)
		default:
			verifiers[cfg.ID] = noneVerifier{}
		}
	}

	return &Service{
		logger:    logger,
		verifiers: verifiers,
	}
}

func (s *Service) Verify(ctx context.Context, input Input) (Result, error) {
	if !input.Bot.Claimed || input.Bot.VerifyType == "none" {
		return Result{
			Verified: false,
			Type:     "none",
			Reason:   "verification_not_required",
		}, nil
	}

	verifier, ok := s.verifiers[input.Bot.ID]
	if !ok {
		return Result{
			Verified: false,
			Type:     input.Bot.VerifyType,
			Reason:   "verifier_not_found",
		}, fmt.Errorf("no verifier registered for bot %q", input.Bot.ID)
	}

	result, err := verifier.Verify(ctx, input.RemoteIP)
	if err != nil {
		result.Type = input.Bot.VerifyType
		if result.Reason == "" {
			result.Reason = "verification_error"
		}
		return result, err
	}

	if result.Type == "" {
		result.Type = input.Bot.VerifyType
	}
	return result, nil
}

func (s *Service) CacheStatus(ctx context.Context, bots []config.BotConfig) []CacheStatus {
	statuses := make([]CacheStatus, 0, len(bots))
	for _, cfg := range bots {
		status := CacheStatus{
			BotID:   cfg.ID,
			BotName: cfg.Name,
			Type:    cfg.Verify.Type,
			State:   "not_applicable",
		}

		if cfg.Verify.Type == "ip_ranges" {
			status.Sources = append([]string(nil), cfg.Verify.Sources...)
			if verifier, ok := s.verifiers[cfg.ID].(*ipRangesVerifier); ok {
				status = verifier.CacheStatus(ctx, status)
			} else {
				status.State = "error"
				status.Error = "ip_ranges verifier not registered"
			}
		}

		statuses = append(statuses, status)
	}
	return statuses
}
