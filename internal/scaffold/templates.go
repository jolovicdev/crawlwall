package scaffold

import (
	"fmt"
	"strings"
)

const Caddyfile = `{
	order crawlwall before reverse_proxy
}

:8080 {
	crawlwall {
		policy ./crawlwall.yaml
		ledger sqlite://./crawlwall.db
		fail_mode block
	}

	reverse_proxy localhost:3000
}
`

const Gitignore = `# Secrets
*.key
*.pem

# Local databases and exports
*.db
*.sqlite
*.sqlite3
*.jsonl

# Local logs
*.log

# Local Caddy binaries
/caddy
/caddy.exe
/caddy-*
/caddy-*.exe

# Local Go build outputs
/crawlwall
/crawlwall.exe
*.test
coverage.out
`

const MinimalPolicy = `version: crawlwall.io/v1

site:
  id: local-dev
  host: localhost
  mode: enforce

runtime:
  fail_mode: block
  default_action:
    type: allow

ledger:
  enabled: true
  sample_humans: false
  write_body_hash: false

receipts:
  enabled: false

bots:
  - id: googlebot
    name: Googlebot
    class: search
    match:
      user_agents:
        - "Googlebot"
    verify:
      type: reverse_dns
      allowed_suffixes:
        - ".googlebot.com"
        - ".google.com"

  - id: gptbot
    name: GPTBot
    class: ai_training
    match:
      user_agents:
        - "GPTBot"
    verify:
      type: ip_ranges
      sources:
        - "https://openai.com/gptbot.json"
      refresh: 1h
      stale_action: fail_closed
      max_stale: 0s

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
    - "/datasets"
    - "/reports"

rules:
  - id: block_spoofed_known_bots
    priority: 10
    when: >
      bot.claimed && !bot.verified
    action:
      type: block
      status: 403
      reason: spoofed_bot

  - id: allow_verified_search
    priority: 100
    when: >
      bot.verified && bot.class == "search"
    action:
      type: allow

  - id: rate_limit_verified_training
    priority: 300
    when: >
      bot.verified && bot.class == "ai_training"
    action:
      type: rate_limit
      limit:
        key: "bot.id"
        rpm: 120

  - id: block_unknown_protected_paths
    priority: 900
    when: >
      bot.class == "unknown" &&
      sets.protected_paths.exists(p, request.path.startsWith(p))
    action:
      type: block
      status: 403
      reason: unknown_crawler_protected_path
`

const FullPolicy = `version: crawlwall.io/v1

site:
  id: local-dev
  host: localhost
  mode: enforce

runtime:
  fail_mode: block
  default_action:
    type: allow

ledger:
  enabled: true
  sample_humans: false
  write_body_hash: false

receipts:
  enabled: true
  signer:
    type: ed25519
    key_file: ./crawlwall.key

bots:
  - id: googlebot
    name: Googlebot
    class: search
    match:
      user_agents:
        - "Googlebot"
    verify:
      type: reverse_dns
      allowed_suffixes:
        - ".googlebot.com"
        - ".google.com"

  - id: gptbot
    name: GPTBot
    class: ai_training
    match:
      user_agents:
        - "GPTBot"
    verify:
      type: ip_ranges
      sources:
        - "https://openai.com/gptbot.json"
      refresh: 1h
      stale_action: fail_closed
      max_stale: 0s

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
    - "/datasets"
    - "/reports"

  known_ai_training:
    - "gptbot"
    - "claudebot"

rules:
  - id: block_spoofed_known_bots
    priority: 10
    when: >
      bot.claimed && !bot.verified
    action:
      type: block
      status: 403
      reason: spoofed_bot
    audit:
      receipt: true
      tags: ["spoofed", "security"]

  - id: allow_verified_search
    priority: 100
    when: >
      bot.verified && bot.class == "search"
    action:
      type: allow
    audit:
      receipt: false
      tags: ["search"]

  - id: meter_training_on_protected_paths
    priority: 200
    when: >
      bot.verified &&
      bot.class == "ai_training" &&
      sets.protected_paths.exists(p, request.path.startsWith(p))
    action:
      type: allow_metered
      price:
        amount: 0.002
        currency: USD
        unit: request
    audit:
      receipt: true
      tags: ["ai_training", "metered"]

  - id: rate_limit_ai_training_elsewhere
    priority: 300
    when: >
      bot.verified && bot.class == "ai_training"
    action:
      type: rate_limit
      limit:
        key: "bot.id"
        rpm: 120
    audit:
      receipt: true
      tags: ["ai_training"]

  - id: block_unknown_protected_paths
    priority: 900
    when: >
      bot.class == "unknown" &&
      sets.protected_paths.exists(p, request.path.startsWith(p))
    action:
      type: block
      status: 403
      reason: unknown_crawler_protected_path
    audit:
      receipt: true
      tags: ["unknown", "blocked"]
`

func Policy(profile string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", "minimal":
		return MinimalPolicy, nil
	case "full":
		return FullPolicy, nil
	default:
		return "", fmt.Errorf("unknown profile %q", profile)
	}
}
