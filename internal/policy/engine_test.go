package policy

import (
	"testing"

	"github.com/jolovicdev/crawlwall/internal/config"
)

func TestEvaluateReturnsMeteredDecisionForVerifiedTrainingBotOnProtectedPath(t *testing.T) {
	cfg := &config.Config{
		Site: config.SiteConfig{
			ID:   "local-dev",
			Host: "localhost",
			Mode: config.SiteModeEnforce,
		},
		Runtime: config.RuntimeConfig{
			FailMode: config.FailModeAllow,
			DefaultAction: config.Action{
				Type: config.ActionAllow,
			},
		},
		Sets: map[string]any{
			"protected_paths": []any{"/archive", "/datasets"},
		},
		Rules: []config.RuleConfig{
			{
				ID:       "meter_training_on_protected_paths",
				Priority: 10,
				When:     `bot.verified && bot.class == "ai_training" && sets.protected_paths.exists(p, request.path.startsWith(p))`,
				Action: config.Action{
					Type: config.ActionAllowMetered,
					Price: &config.Price{
						Amount:   0.002,
						Currency: "USD",
						Unit:     "request",
					},
				},
			},
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision, err := engine.Evaluate(Input{
		Bot: BotInput{
			ID:       "gptbot",
			Class:    "ai_training",
			Claimed:  true,
			Verified: true,
		},
		Request: RequestInput{
			Path: "/archive/page-a",
		},
		Site:   engine.SiteInput(),
		Sets:   engine.SetsInput(),
		Labels: map[string]any{},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	if decision.RuleID != "meter_training_on_protected_paths" {
		t.Fatalf("decision.RuleID = %q", decision.RuleID)
	}
	if decision.Action.Type != config.ActionAllowMetered {
		t.Fatalf("decision.Action.Type = %q", decision.Action.Type)
	}
}

func TestEvaluateReturnsErrorForRuntimeCELError(t *testing.T) {
	cfg := &config.Config{
		Site: config.SiteConfig{
			ID:   "local-dev",
			Host: "localhost",
			Mode: config.SiteModeEnforce,
		},
		Runtime: config.RuntimeConfig{
			FailMode: config.FailModeBlock,
			DefaultAction: config.Action{
				Type: config.ActionAllow,
			},
		},
		Sets: map[string]any{
			"protected_paths": "not-a-list",
		},
		Rules: []config.RuleConfig{
			{
				ID:       "bad_dynamic_set_shape",
				Priority: 10,
				When:     `sets.protected_paths.exists(p, request.path.startsWith(p))`,
				Action: config.Action{
					Type:   config.ActionBlock,
					Status: 403,
					Reason: "blocked",
				},
			},
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	_, err = engine.Evaluate(Input{
		Bot:     BotInput{ID: "unknown", Class: "unknown"},
		Request: RequestInput{Path: "/archive/page-a"},
		Site:    engine.SiteInput(),
		Sets:    engine.SetsInput(),
		Labels:  map[string]any{},
	})
	if err == nil {
		t.Fatalf("Evaluate() error = nil, want runtime CEL error")
	}
}
