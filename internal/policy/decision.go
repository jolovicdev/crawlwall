package policy

import "github.com/jolovicdev/crawlwall/v2/internal/config"

type Decision struct {
	RuleID string
	Action config.Action
	Audit  config.Audit
}
