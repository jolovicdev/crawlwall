# CrawlWall Policy Guide

CrawlWall policies are YAML files with CEL expressions in `rules[].when`.
You do not need to learn all of CEL to use CrawlWall. You need a small set of
boolean expressions over the request, bot identity, site metadata, reusable
sets, and counters.

## Rule Shape

Every rule has five normal parts:

```yaml
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
```

| Field | Purpose |
| --- | --- |
| `id` | Stable name for logs, fixtures, and reports |
| `priority` | Lower numbers run first |
| `when` | CEL expression that returns `true` or `false` |
| `action` | What CrawlWall should decide |
| `audit` | Optional receipt and tag settings |

Rules are evaluated by ascending priority. The first matching rule wins. If no
rule matches, `runtime.default_action` is used.

## Modes

Use `site.mode` to control whether matching decisions are enforced:

```yaml
site:
  id: docs-prod
  host: docs.example.com
  mode: shadow
```

| Mode | Behavior |
| --- | --- |
| `shadow` | Log decisions, but do not block or rate-limit traffic |
| `observe` | Alias for `shadow`, kept for older configs |
| `enforce` | Apply block and rate-limit decisions |

Start production policy changes in `shadow`, inspect the ledger, then switch to
`enforce` after the results look sane.

## Available Inputs

### `bot`

| Name | Type | Meaning |
| --- | --- | --- |
| `bot.id` | string | Configured bot ID, such as `gptbot` or `unknown` |
| `bot.name` | string | Human-readable bot name |
| `bot.class` | string | Bot class, such as `search` or `ai_training` |
| `bot.claimed` | bool | Request matched a configured bot user agent |
| `bot.verified` | bool | Source verification succeeded |
| `bot.operator` | string | Optional operator label from config |

### `request`

| Name | Type | Meaning |
| --- | --- | --- |
| `request.host` | string | Request host |
| `request.method` | string | HTTP method |
| `request.path` | string | URL path |
| `request.query` | string | Raw query string |
| `request.ip` | string | Trusted client IP as seen by Caddy |
| `request.user_agent` | string | User-Agent header |
| `request.headers` | map | Lowercase request headers |

### `site`, `sets`, and `counters`

`site` contains `id`, `host`, and `mode`.

`sets` contains reusable values from your policy:

```yaml
sets:
  protected_paths:
    - "/archive"
    - "/datasets"
```

`counters` currently exposes basic request grouping fields:

| Name | Meaning |
| --- | --- |
| `counters.bot_id` | Identified bot ID |
| `counters.host` | Request host |
| `counters.path` | Request path |

## CEL Basics

Useful operators:

| Expression | Meaning |
| --- | --- |
| `a && b` | both must be true |
| `a \|\| b` | either may be true |
| `!a` | not |
| `x == "value"` | equality |
| `x != "value"` | inequality |
| `list.exists(x, condition)` | true if any list item matches |
| `text.startsWith("/path")` | string prefix check |
| `text.contains("GPTBot")` | string contains check |

Avoid clever expressions at first. A boring rule that you can explain later is
better than a clever rule that blocks the wrong crawler at 2 AM.

## Recipes

### Block Spoofed Known Bots

```yaml
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
```

### Allow Verified Search Crawlers

```yaml
- id: allow_verified_search
  priority: 100
  when: >
    bot.verified && bot.class == "search"
  action:
    type: allow
```

### Meter Verified AI Crawlers on Protected Paths

```yaml
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
```

### Rate-Limit Verified AI Crawlers Elsewhere

```yaml
- id: rate_limit_ai_training_elsewhere
  priority: 300
  when: >
    bot.verified && bot.class == "ai_training"
  action:
    type: rate_limit
    limit:
      key: "bot.id"
      rpm: 120
```

### Block Unknown Crawlers on Protected Paths

```yaml
- id: block_unknown_protected_paths
  priority: 900
  when: >
    bot.class == "unknown" &&
    sets.protected_paths.exists(p, request.path.startsWith(p))
  action:
    type: block
    status: 403
    reason: unknown_crawler_protected_path
```

## Testing Policies

Validate syntax and compile CEL:

```sh
go run ./cmd/crawlwall policy check --config ./crawlwall.yaml
```

Evaluate one request:

```sh
go run ./cmd/crawlwall policy eval \
  --config ./crawlwall.yaml --ua "GPTBot/1.1" \
  --path "/archive/a" --ip 20.125.66.81
```

Run fixture tests:

```sh
go run ./cmd/crawlwall policy test --config ./crawlwall.yaml --fixtures ./examples/policy-fixtures.yaml
```

Fixture files look like this:

```yaml
fixtures:
  - name: unknown crawler is blocked from archive
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
```

Each expected field is optional. Leave out fields that do not matter for the
case.

## Verifier Cache Status

Check verifier source health before trusting policy results:

```sh
go run ./cmd/crawlwall verifiers status --config ./crawlwall.yaml
```

For IP range verifiers, this reports source fetch state, CIDR count, last fetch
time, expiry, stale policy, and errors. Reverse DNS and `none` verifiers do not
have an IP range cache, so their state is `not_applicable`.

## IP Range Freshness

For bots such as GPTBot, published IP ranges are cached in memory. That means a
range rotation is only seen after the next refresh. Pick the refresh interval
with that tradeoff in mind.

Security-first:

```yaml
verify:
  type: ip_ranges
  sources:
    - "https://openai.com/gptbot.json"
  refresh: 1h
  stale_action: fail_closed
  max_stale: 0s
```

Availability-first:

```yaml
verify:
  type: ip_ranges
  sources:
    - "https://openai.com/gptbot.json"
  refresh: 1h
  stale_action: use_stale
  max_stale: 24h
```

`fail_closed` refuses to trust expired ranges after a failed refresh. `use_stale`
keeps using expired ranges, but only until `max_stale` is reached.
