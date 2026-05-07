package policy

import "github.com/jolovicdev/crawlwall/internal/config"

type Decision struct {
	RuleID string
	Action config.Action
	Audit  config.Audit
}
