package bot

import "github.com/jolovicdev/crawlwall/v2/internal/config"

func NewRegistry(cfgs []config.BotConfig) []Registered {
	out := make([]Registered, 0, len(cfgs))
	for _, cfg := range cfgs {
		out = append(out, Registered{
			ID:       cfg.ID,
			Name:     cfg.Name,
			Class:    cfg.Class,
			Operator: cfg.Operator,
			Match:    cfg.Match,
			Verify:   cfg.Verify,
		})
	}
	return out
}
