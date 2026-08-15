package bot

import (
	"strings"

	"github.com/jolovicdev/crawlwall/internal/config"
)

// matcher pairs the lowercased user-agent needles for one bot with the result
// Identify returns when any of them hits. Both are built once at provision time
// so the request path only scans bytes.
type matcher struct {
	needles    []string
	identified Identified
}

type Identifier struct {
	matchers   []matcher
	defaultBot Identified
}

func NewIdentifier(cfgs []config.BotConfig) *Identifier {
	registry := NewRegistry(cfgs)
	identifier := &Identifier{
		matchers: make([]matcher, 0, len(registry)),
		defaultBot: Identified{
			ID:         "unknown",
			Name:       "Unknown",
			Class:      "unknown",
			VerifyType: "none",
			Verify:     config.VerifyConfig{Type: "none"},
		},
	}

	for _, registered := range registry {
		identified := Identified{
			ID:         registered.ID,
			Name:       registered.Name,
			Class:      registered.Class,
			Operator:   registered.Operator,
			VerifyType: registered.Verify.Type,
			Verify:     registered.Verify,
		}

		if registered.Match.Default {
			identifier.defaultBot = identified
		}

		needles := make([]string, 0, len(registered.Match.UserAgents))
		for _, needle := range registered.Match.UserAgents {
			if needle = strings.ToLower(strings.TrimSpace(needle)); needle != "" {
				needles = append(needles, needle)
			}
		}
		if len(needles) == 0 {
			continue
		}

		identified.Claimed = true
		identifier.matchers = append(identifier.matchers, matcher{needles: needles, identified: identified})
	}

	return identifier
}

func (i *Identifier) Identify(userAgent string) Identified {
	for _, m := range i.matchers {
		for _, needle := range m.needles {
			if containsFold(userAgent, needle) {
				return m.identified
			}
		}
	}

	return i.defaultBot
}

// containsFold reports whether s contains lowerNeedle, folding ASCII case in s.
// lowerNeedle must already be lowercase. Unlike strings.Contains(strings.ToLower(s), …)
// it allocates nothing, which matters because it runs on every request.
func containsFold(s, lowerNeedle string) bool {
	n := len(lowerNeedle)
	if n == 0 {
		return true
	}
outer:
	for i := 0; i+n <= len(s); i++ {
		for j := 0; j < n; j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != lowerNeedle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}
