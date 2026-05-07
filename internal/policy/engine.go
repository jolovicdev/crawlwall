package policy

import (
	"fmt"
	"net/http"

	"github.com/jolovicdev/crawlwall/internal/bot"
	"github.com/jolovicdev/crawlwall/internal/config"
)

type Engine struct {
	rules         []compiledRule
	sets          map[string]any
	site          map[string]any
	defaultAction config.Action
}

func NewEngine(cfg *config.Config) (*Engine, error) {
	env, err := newEnv()
	if err != nil {
		return nil, err
	}

	rules, err := compileRules(env, cfg.Rules)
	if err != nil {
		return nil, err
	}

	site := map[string]any{
		"id":   cfg.Site.ID,
		"host": cfg.Site.Host,
		"mode": cfg.Site.Mode,
	}
	sets := cfg.Sets
	if sets == nil {
		sets = map[string]any{}
	}

	return &Engine{
		rules:         rules,
		sets:          sets,
		site:          site,
		defaultAction: cfg.Runtime.DefaultAction,
	}, nil
}

func (e *Engine) Evaluate(input Input) (Decision, error) {
	vars := input.Vars()
	for _, rule := range e.rules {
		out, _, err := rule.Program.Eval(vars)
		if err != nil {
			return Decision{}, fmt.Errorf("evaluate rule %s: %w", rule.ID, err)
		}

		matched, ok := out.Value().(bool)
		if !ok || !matched {
			continue
		}

		return Decision{
			RuleID: rule.ID,
			Action: rule.Action,
			Audit:  rule.Audit,
		}, nil
	}

	return e.DefaultDecision(), nil
}

func (e *Engine) DefaultDecision() Decision {
	return Decision{
		RuleID: "runtime.default_action",
		Action: e.normalizedAction(e.defaultAction),
	}
}

func (e *Engine) EvaluationErrorDecision(failMode string) Decision {
	if failMode == config.FailModeAllow {
		return Decision{
			RuleID: "runtime.policy_error",
			Action: config.Action{
				Type:   config.ActionAllow,
				Reason: "policy_evaluation_failed",
			},
		}
	}

	return Decision{
		RuleID: "runtime.policy_error",
		Action: config.Action{
			Type:   config.ActionBlock,
			Status: http.StatusInternalServerError,
			Reason: "policy_evaluation_failed",
		},
	}
}

func (e *Engine) SiteInput() map[string]any {
	return cloneMap(e.site)
}

func (e *Engine) SetsInput() map[string]any {
	return cloneMap(e.sets)
}

func (e *Engine) LabelsInput(identified bot.Identified, r *http.Request) map[string]any {
	return DefaultLabelsInput(identified, r)
}

func (e *Engine) normalizedAction(action config.Action) config.Action {
	if action.Type == config.ActionBlock && action.Status == 0 {
		action.Status = http.StatusForbidden
	}
	return action
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}

	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = cloneValue(value)
	}
	return out
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneValue(item)
		}
		return out
	default:
		return typed
	}
}

func DescribeDecision(decision Decision) string {
	switch decision.Action.Type {
	case config.ActionBlock:
		return fmt.Sprintf("%s -> block (%d %s)", decision.RuleID, decision.Action.Status, decision.Action.Reason)
	case config.ActionRateLimit:
		if decision.Action.Limit == nil {
			return fmt.Sprintf("%s -> rate_limit", decision.RuleID)
		}
		return fmt.Sprintf("%s -> rate_limit (%s @ %drpm)", decision.RuleID, decision.Action.Limit.Key, decision.Action.Limit.RPM)
	case config.ActionAllowMetered:
		if decision.Action.Price == nil {
			return fmt.Sprintf("%s -> allow_metered", decision.RuleID)
		}
		return fmt.Sprintf("%s -> allow_metered (%.4f %s/%s)", decision.RuleID, decision.Action.Price.Amount, decision.Action.Price.Currency, decision.Action.Price.Unit)
	default:
		return fmt.Sprintf("%s -> allow", decision.RuleID)
	}
}
