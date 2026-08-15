package bot

import (
	"strings"
	"unicode/utf8"

	"github.com/jolovicdev/crawlwall/v2/internal/config"
)

// matcher pairs the lowercased user-agent needles for one bot with the result
// Identify returns when any of them hits. Both are built once at provision time
// so the request path only scans bytes.
type matcher struct {
	needles    []needle
	identified Identified
}

type needle struct {
	text string
	// ascii marks a needle containsFold can match byte by byte. A needle with
	// a non-ASCII letter needs real Unicode folding, so those fall back to
	// matching against a lowercased copy of the user agent.
	ascii bool
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

		needles := make([]needle, 0, len(registered.Match.UserAgents))
		for _, configured := range registered.Match.UserAgents {
			if folded := strings.ToLower(strings.TrimSpace(configured)); folded != "" {
				needles = append(needles, needle{text: folded, ascii: isASCII(folded)})
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
	// Lowercased lazily, and only when a non-ASCII needle is configured; the
	// common all-ASCII configuration never allocates here.
	lowered := ""
	loweredReady := false

	for _, m := range i.matchers {
		for _, n := range m.needles {
			if n.ascii {
				if containsFold(userAgent, n.text) {
					return m.identified
				}
				continue
			}
			if !loweredReady {
				lowered = strings.ToLower(userAgent)
				loweredReady = true
			}
			if strings.Contains(lowered, n.text) {
				return m.identified
			}
		}
	}

	return i.defaultBot
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
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
