package bot

import (
	"strings"

	"github.com/jolovicdev/crawlwall/internal/config"
)

type Identifier struct {
	bots       []Registered
	defaultBot Registered
}

func NewIdentifier(cfgs []config.BotConfig) *Identifier {
	registry := NewRegistry(cfgs)
	identifier := &Identifier{
		bots: registry,
		defaultBot: Registered{
			ID:     "unknown",
			Name:   "Unknown",
			Class:  "unknown",
			Verify: config.VerifyConfig{Type: "none"},
		},
	}

	for _, registered := range registry {
		if registered.Match.Default {
			identifier.defaultBot = registered
			break
		}
	}

	return identifier
}

func (i *Identifier) Identify(userAgent string) Identified {
	ua := strings.ToLower(userAgent)
	for _, registered := range i.bots {
		for _, needle := range registered.Match.UserAgents {
			if strings.Contains(ua, strings.ToLower(needle)) {
				return Identified{
					ID:         registered.ID,
					Name:       registered.Name,
					Class:      registered.Class,
					Operator:   registered.Operator,
					Claimed:    true,
					VerifyType: registered.Verify.Type,
					Verify:     registered.Verify,
				}
			}
		}
	}

	return Identified{
		ID:         i.defaultBot.ID,
		Name:       i.defaultBot.Name,
		Class:      i.defaultBot.Class,
		Operator:   i.defaultBot.Operator,
		Claimed:    false,
		VerifyType: i.defaultBot.Verify.Type,
		Verify:     i.defaultBot.Verify,
	}
}
