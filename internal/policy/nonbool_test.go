package policy

import (
	"strings"
	"testing"

	"github.com/jolovicdev/crawlwall/internal/config"
)

// A rule whose expression is not a boolean never matches. For a block rule that
// is a silent policy bypass, so it must be loud instead: rejected at compile
// time when the type is statically known, and an evaluation error otherwise.
func TestNewEngineRejectsStaticallyNonBooleanRule(t *testing.T) {
	_, err := NewEngine(&config.Config{
		Rules: []config.RuleConfig{{
			ID:     "typo",
			When:   `"always"`,
			Action: config.Action{Type: config.ActionBlock, Status: 403, Reason: "nope"},
		}},
	})
	if err == nil {
		t.Fatalf("NewEngine() error = nil, want a rejection for a non-boolean rule")
	}
	if !strings.Contains(err.Error(), "must evaluate to a boolean") {
		t.Fatalf("NewEngine() error = %v, want a boolean type complaint", err)
	}
}

func TestEvaluateReportsNonBooleanRuleAtRuntime(t *testing.T) {
	// request.path is dyn-typed, so the compiler cannot catch it; evaluation
	// must surface it rather than quietly skipping the rule.
	engine, err := NewEngine(&config.Config{
		Rules: []config.RuleConfig{{
			ID:     "typo",
			When:   `request.path`,
			Action: config.Action{Type: config.ActionBlock, Status: 403, Reason: "nope"},
		}},
		Runtime: config.RuntimeConfig{DefaultAction: config.Action{Type: config.ActionAllow}},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	_, err = engine.Evaluate(Input{Request: RequestInput{Path: "/archive"}})
	if err == nil {
		t.Fatalf("Evaluate() error = nil, want a non-boolean rule error")
	}
	if !strings.Contains(err.Error(), "want bool") {
		t.Fatalf("Evaluate() error = %v, want a bool complaint", err)
	}
}

func TestNewEngineAcceptsDynBooleanRule(t *testing.T) {
	// `bot.verified` is dyn-typed but genuinely boolean at runtime; rejecting
	// it would break ordinary policies.
	engine, err := NewEngine(&config.Config{
		Rules: []config.RuleConfig{{
			ID:     "spoofed",
			When:   `bot.verified`,
			Action: config.Action{Type: config.ActionAllow},
		}},
		Runtime: config.RuntimeConfig{DefaultAction: config.Action{Type: config.ActionBlock, Status: 403, Reason: "default"}},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	decision, err := engine.Evaluate(Input{Bot: BotInput{Verified: true}})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.RuleID != "spoofed" {
		t.Fatalf("decision.RuleID = %q, want spoofed", decision.RuleID)
	}
}
