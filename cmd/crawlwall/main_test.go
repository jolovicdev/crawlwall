package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestInitWritesMinimalScaffold(t *testing.T) {
	dir := t.TempDir()

	if err := runInit([]string{"--dir", dir, "--profile", "minimal", "--generate-keys=false"}); err != nil {
		t.Fatalf("runInit() error = %v", err)
	}

	for _, name := range []string{"crawlwall.yaml", "Caddyfile", ".gitignore"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}

	if _, err := os.Stat(filepath.Join(dir, "crawlwall.key")); !os.IsNotExist(err) {
		t.Fatalf("expected no private key file, got err=%v", err)
	}
}

func TestInitWritesKeysForFullProfile(t *testing.T) {
	dir := t.TempDir()

	if err := runInit([]string{"--dir", dir, "--profile", "full"}); err != nil {
		t.Fatalf("runInit() error = %v", err)
	}

	for _, name := range []string{"crawlwall.yaml", "crawlwall.key", "crawlwall.pub"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}
}

func TestPolicyTestRunsFixtures(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "crawlwall.yaml")
	fixturesPath := filepath.Join(dir, "policy-fixtures.yaml")

	writeTestFile(t, configPath, `version: crawlwall.io/v1

site:
  id: test-site
  host: localhost
  mode: enforce

runtime:
  fail_mode: block
  default_action:
    type: allow

ledger:
  enabled: false

receipts:
  enabled: false

bots:
  - id: unknown
    name: Unknown
    class: unknown
    match:
      default: true
    verify:
      type: none

sets:
  protected_paths:
    - "/archive"

rules:
  - id: block_unknown_protected_paths
    priority: 10
    when: >
      bot.class == "unknown" &&
      sets.protected_paths.exists(p, request.path.startsWith(p))
    action:
      type: block
      status: 403
      reason: unknown_crawler_protected_path
`)

	writeTestFile(t, fixturesPath, `fixtures:
  - name: unknown crawler is blocked from protected path
    request:
      user_agent: "curl/8.0"
      path: "/archive/a"
      ip: "198.51.100.10"
    expect:
      bot_id: unknown
      verified: false
      rule_id: block_unknown_protected_paths
      action: block
      reason: unknown_crawler_protected_path
      status: 403
`)

	if err := runPolicy(context.Background(), []string{"test", "--config", configPath, "--fixtures", fixturesPath}); err != nil {
		t.Fatalf("runPolicy(test) error = %v", err)
	}
}

func TestVerifiersStatusFetchesIPRanges(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "crawlwall.yaml")

	server := newTestIPRangeServer(t, `{"prefixes":[{"ipv4Prefix":"20.125.66.80/28"}]}`)
	writeTestFile(t, configPath, `version: crawlwall.io/v1

site:
  id: test-site
  host: localhost
  mode: shadow

runtime:
  fail_mode: block
  default_action:
    type: allow

ledger:
  enabled: false

receipts:
  enabled: false

bots:
  - id: gptbot
    name: GPTBot
    class: ai_training
    match:
      user_agents:
        - "GPTBot"
    verify:
      type: ip_ranges
      sources:
        - "`+server+`"
      refresh: 1h

  - id: unknown
    name: Unknown
    class: unknown
    match:
      default: true
    verify:
      type: none

rules:
  - id: allow_all
    priority: 100
    when: >
      true
    action:
      type: allow
`)

	if err := runVerifiers(context.Background(), []string{"status", "--config", configPath}); err != nil {
		t.Fatalf("runVerifiers(status) error = %v", err)
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func newTestIPRangeServer(t *testing.T, body string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server.URL
}
