package scaffold

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jolovicdev/crawlwall/internal/config"
	"github.com/jolovicdev/crawlwall/internal/policy"
)

func TestPolicyProfilesLoadValidateAndCompile(t *testing.T) {
	for _, profile := range []string{"", "minimal", "full"} {
		text, err := Policy(profile)
		if err != nil {
			t.Fatalf("Policy(%q) error = %v", profile, err)
		}
		if text == "" {
			t.Fatalf("Policy(%q) returned empty text", profile)
		}

		path := filepath.Join(t.TempDir(), "crawlwall.yaml")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		cfg, err := config.LoadFile(path)
		if err != nil {
			t.Fatalf("LoadFile(%q) error = %v", profile, err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate(%q) error = %v", profile, err)
		}
		if _, err := policy.NewEngine(cfg); err != nil {
			t.Fatalf("NewEngine(%q) error = %v", profile, err)
		}
	}
}

func TestPolicyUnknownProfileErrors(t *testing.T) {
	if _, err := Policy("bogus"); err == nil {
		t.Fatalf("Policy(\"bogus\") error = nil, want error")
	}
}

func TestStaticTemplatesNotEmpty(t *testing.T) {
	if Caddyfile == "" {
		t.Fatalf("Caddyfile template is empty")
	}
	if Gitignore == "" {
		t.Fatalf("Gitignore template is empty")
	}
}
