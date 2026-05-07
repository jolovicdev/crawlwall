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
