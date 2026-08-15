package bot

import (
	"testing"

	"github.com/jolovicdev/crawlwall/internal/config"
)

func TestIdentifyFallsBackToDefaultBot(t *testing.T) {
	identifier := NewIdentifier([]config.BotConfig{
		{
			ID:    "googlebot",
			Name:  "Googlebot",
			Class: "search",
			Match: config.MatchConfig{
				UserAgents: []string{"Googlebot"},
			},
			Verify: config.VerifyConfig{Type: "reverse_dns"},
		},
		{
			ID:    "unknown",
			Name:  "Unknown",
			Class: "unknown",
			Match: config.MatchConfig{
				Default: true,
			},
			Verify: config.VerifyConfig{Type: "none"},
		},
	})

	identified := identifier.Identify("curl/8.0")
	if identified.ID != "unknown" {
		t.Fatalf("identified.ID = %q", identified.ID)
	}
	if identified.Claimed {
		t.Fatalf("identified.Claimed = true")
	}
}

func TestIdentifyIsCaseInsensitiveWithoutAllocating(t *testing.T) {
	identifier := NewIdentifier([]config.BotConfig{
		{ID: "gptbot", Name: "GPTBot", Class: "ai_training", Match: config.MatchConfig{UserAgents: []string{"GPTBot"}}},
		{ID: "unknown", Name: "Unknown", Class: "unknown", Match: config.MatchConfig{Default: true}},
	})

	for _, userAgent := range []string{
		"Mozilla/5.0 (compatible; GPTBot/1.1)",
		"mozilla/5.0 (compatible; gptbot/1.1)",
		"MOZILLA/5.0 (COMPATIBLE; GPTBOT/1.1)",
	} {
		if got := identifier.Identify(userAgent); got.ID != "gptbot" || !got.Claimed {
			t.Fatalf("Identify(%q) = %+v, want a claimed gptbot", userAgent, got)
		}
	}

	// Identification runs on every request, so it must not allocate.
	allocs := testing.AllocsPerRun(100, func() {
		identifier.Identify("Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)")
	})
	if allocs != 0 {
		t.Fatalf("Identify() allocs = %v, want 0", allocs)
	}
}

func TestIdentifyDefaultBotIsNotClaimed(t *testing.T) {
	identifier := NewIdentifier([]config.BotConfig{
		{ID: "gptbot", Name: "GPTBot", Class: "ai_training", Match: config.MatchConfig{UserAgents: []string{"GPTBot"}}},
		{ID: "unknown", Name: "Unknown", Class: "unknown", Match: config.MatchConfig{Default: true}},
	})

	got := identifier.Identify("curl/8.0")
	if got.ID != "unknown" || got.Claimed {
		t.Fatalf("Identify() = %+v, want an unclaimed unknown", got)
	}
}

func BenchmarkIdentify(b *testing.B) {
	identifier := NewIdentifier([]config.BotConfig{
		{ID: "googlebot", Name: "Googlebot", Class: "search", Match: config.MatchConfig{UserAgents: []string{"Googlebot"}}},
		{ID: "bingbot", Name: "Bingbot", Class: "search", Match: config.MatchConfig{UserAgents: []string{"bingbot"}}},
		{ID: "gptbot", Name: "GPTBot", Class: "ai_training", Match: config.MatchConfig{UserAgents: []string{"GPTBot", "ChatGPT-User", "OAI-SearchBot"}}},
		{ID: "unknown", Name: "Unknown", Class: "unknown", Match: config.MatchConfig{Default: true}},
	})
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		identifier.Identify(userAgent)
	}
}

// A needle with a non-ASCII letter cannot be matched by ASCII folding alone;
// it must keep the Unicode case-insensitivity the pre-matcher code had.
func TestIdentifyNonASCIINeedleStaysCaseInsensitive(t *testing.T) {
	identifier := NewIdentifier([]config.BotConfig{
		{ID: "uni", Name: "Ünicorn", Class: "other", Match: config.MatchConfig{UserAgents: []string{"Ünicorn"}}},
		{ID: "unknown", Name: "Unknown", Class: "unknown", Match: config.MatchConfig{Default: true}},
	})

	if got := identifier.Identify("Mozilla/5.0 ÜNICORN/2.0"); got.ID != "uni" {
		t.Fatalf("Identify(upper-case UA) = %q, want uni", got.ID)
	}
}
