package config

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (c *Config) Validate() error {
	if c.Version != VersionV1 {
		return fmt.Errorf("unsupported crawlwall version %q", c.Version)
	}
	if strings.TrimSpace(c.Site.ID) == "" {
		return fmt.Errorf("site.id is required")
	}
	if strings.TrimSpace(c.Site.Host) == "" {
		return fmt.Errorf("site.host is required")
	}
	if c.Site.Mode != SiteModeObserve && c.Site.Mode != SiteModeEnforce && c.Site.Mode != SiteModeShadow {
		return fmt.Errorf("site.mode must be %q, %q, or %q", SiteModeEnforce, SiteModeShadow, SiteModeObserve)
	}
	if c.Runtime.FailMode != FailModeAllow && c.Runtime.FailMode != FailModeBlock {
		return fmt.Errorf("runtime.fail_mode must be %q or %q", FailModeAllow, FailModeBlock)
	}
	if err := validateAction("runtime.default_action", c.Runtime.DefaultAction); err != nil {
		return err
	}

	if c.Receipts.Enabled {
		if c.Receipts.Signer.Type != "ed25519" {
			return fmt.Errorf("receipts.signer.type must be ed25519")
		}
		if strings.TrimSpace(c.Receipts.Signer.KeyFile) == "" {
			return fmt.Errorf("receipts.signer.key_file is required when receipts are enabled")
		}
	}

	if len(c.Bots) == 0 {
		return fmt.Errorf("at least one bot definition is required")
	}

	defaults := 0
	seenBots := map[string]struct{}{}
	for _, bot := range c.Bots {
		if strings.TrimSpace(bot.ID) == "" {
			return fmt.Errorf("bot.id is required")
		}
		if _, exists := seenBots[bot.ID]; exists {
			return fmt.Errorf("duplicate bot.id %q", bot.ID)
		}
		seenBots[bot.ID] = struct{}{}

		if strings.TrimSpace(bot.Name) == "" {
			return fmt.Errorf("bot %q: name is required", bot.ID)
		}
		if strings.TrimSpace(bot.Class) == "" {
			return fmt.Errorf("bot %q: class is required", bot.ID)
		}
		if bot.Match.Default {
			defaults++
		}
		if !bot.Match.Default && len(bot.Match.UserAgents) == 0 {
			return fmt.Errorf("bot %q: at least one match.user_agents entry is required", bot.ID)
		}
		switch bot.Verify.Type {
		case "none":
		case "reverse_dns":
			if len(bot.Verify.AllowedSuffixes) == 0 {
				return fmt.Errorf("bot %q: reverse_dns verifier requires allowed_suffixes", bot.ID)
			}
		case "ip_ranges":
			if len(bot.Verify.Sources) == 0 {
				return fmt.Errorf("bot %q: ip_ranges verifier requires sources", bot.ID)
			}
			if bot.Verify.Refresh != "" {
				if _, err := time.ParseDuration(bot.Verify.Refresh); err != nil {
					return fmt.Errorf("bot %q: invalid verify.refresh: %w", bot.ID, err)
				}
			}
			if bot.Verify.MaxStale != "" {
				if _, err := time.ParseDuration(bot.Verify.MaxStale); err != nil {
					return fmt.Errorf("bot %q: invalid verify.max_stale: %w", bot.ID, err)
				}
			}
			switch bot.Verify.StaleAction {
			case "", StaleActionFailClosed, StaleActionUseStale:
			default:
				return fmt.Errorf("bot %q: verify.stale_action must be %q or %q", bot.ID, StaleActionFailClosed, StaleActionUseStale)
			}
		default:
			return fmt.Errorf("bot %q: unsupported verify.type %q", bot.ID, bot.Verify.Type)
		}
	}

	if defaults != 1 {
		return fmt.Errorf("exactly one bot.match.default entry is required")
	}

	seenRules := map[string]struct{}{}
	for _, rule := range c.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("rule.id is required")
		}
		if _, exists := seenRules[rule.ID]; exists {
			return fmt.Errorf("duplicate rule.id %q", rule.ID)
		}
		seenRules[rule.ID] = struct{}{}
		if strings.TrimSpace(rule.When) == "" {
			return fmt.Errorf("rule %q: when is required", rule.ID)
		}
		if err := validateAction("rule "+rule.ID, rule.Action); err != nil {
			return err
		}
	}

	return nil
}

func validateAction(scope string, action Action) error {
	switch action.Type {
	case ActionAllow:
	case ActionBlock:
		if action.Status == 0 {
			action.Status = http.StatusForbidden
		}
		if action.Status < 100 || action.Status > 599 {
			return fmt.Errorf("%s: block status must be a valid HTTP status", scope)
		}
		if strings.TrimSpace(action.Reason) == "" {
			return fmt.Errorf("%s: block action requires reason", scope)
		}
	case ActionRateLimit:
		if action.Limit == nil {
			return fmt.Errorf("%s: rate_limit action requires limit", scope)
		}
		if strings.TrimSpace(action.Limit.Key) == "" {
			return fmt.Errorf("%s: rate_limit limit.key is required", scope)
		}
		if action.Limit.RPM <= 0 {
			return fmt.Errorf("%s: rate_limit limit.rpm must be positive", scope)
		}
	case ActionAllowMetered:
		if action.Price == nil {
			return fmt.Errorf("%s: allow_metered action requires price", scope)
		}
		if action.Price.Amount <= 0 {
			return fmt.Errorf("%s: allow_metered price.amount must be positive", scope)
		}
		if strings.TrimSpace(action.Price.Currency) == "" || strings.TrimSpace(action.Price.Unit) == "" {
			return fmt.Errorf("%s: allow_metered price.currency and price.unit are required", scope)
		}
	default:
		return fmt.Errorf("%s: unsupported action type %q", scope, action.Type)
	}

	return nil
}
