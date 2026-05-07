package policy

import (
	"fmt"
	"sort"

	"github.com/google/cel-go/cel"

	"github.com/jolovicdev/crawlwall/internal/config"
)

type compiledRule struct {
	ID       string
	Priority int
	When     string
	Action   config.Action
	Audit    config.Audit
	Program  cel.Program
}

func compileRules(env *cel.Env, rules []config.RuleConfig) ([]compiledRule, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		ast, issues := env.Compile(rule.When)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("compile rule %s: %w", rule.ID, issues.Err())
		}

		program, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("program rule %s: %w", rule.ID, err)
		}

		compiled = append(compiled, compiledRule{
			ID:       rule.ID,
			Priority: rule.Priority,
			When:     rule.When,
			Action:   rule.Action,
			Audit:    rule.Audit,
			Program:  program,
		})
	}

	sort.Slice(compiled, func(i, j int) bool {
		if compiled[i].Priority == compiled[j].Priority {
			return compiled[i].ID < compiled[j].ID
		}
		return compiled[i].Priority < compiled[j].Priority
	})

	return compiled, nil
}
