package config

import "testing"

func baseValidConfig() *Config {
	return &Config{
		Version: VersionV1,
		Site:    SiteConfig{ID: "s", Host: "h", Mode: SiteModeEnforce},
		Runtime: RuntimeConfig{FailMode: FailModeBlock, DefaultAction: Action{Type: ActionAllow}},
		Bots: []BotConfig{
			{ID: "unknown", Name: "Unknown", Class: "unknown", Match: MatchConfig{Default: true}, Verify: VerifyConfig{Type: "none"}},
		},
	}
}

func TestValidateRejectsUnresolvableLimitKey(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Rules = []RuleConfig{{
		ID:     "rl",
		When:   "true",
		Action: Action{Type: ActionRateLimit, Limit: &Limit{Key: "bot.nope", RPM: 60}},
	}}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate() error = nil, want unresolvable limit.key error")
	}
}

func TestValidateAcceptsKnownLimitKeys(t *testing.T) {
	keys := []string{"bot.id", "request.ip", "request.path", "labels.bot_id", "request.headers.cf-connecting-ip"}
	for _, key := range keys {
		cfg := baseValidConfig()
		cfg.Rules = []RuleConfig{{
			ID:     "rl",
			When:   "true",
			Action: Action{Type: ActionRateLimit, Limit: &Limit{Key: key, RPM: 60}},
		}}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() with limit.key %q error = %v", key, err)
		}
	}
}
