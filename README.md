# CrawlWall — Block AI Crawlers at the Edge with Caddy

[![Go Reference](https://pkg.go.dev/badge/github.com/jolovicdev/crawlwall.svg)](https://pkg.go.dev/github.com/jolovicdev/crawlwall)
[![Go version](https://img.shields.io/github/go-mod/go-version/jolovicdev/crawlwall)](go.mod)
[![License: MIT](https://img.shields.io/github/license/jolovicdev/crawlwall)](LICENSE)

**Self-hosted AI crawler blocking, bot verification, and rate limiting for
[Caddy](https://caddyserver.com).** Block AI scrapers such as GPTBot, ClaudeBot,
and PerplexityBot while still allowing verified search engines like Googlebot
and Bingbot — enforced at the HTTP edge, not suggested in a text file.

CrawlWall turns crawler policy into rules your server actually applies. It
identifies bots by user agent, verifies who they really are with reverse DNS or
published IP ranges, evaluates [CEL](https://cel.dev) policy, and records every
decision in an auditable ledger.

```
robots.txt  →  "please don't crawl this"        (advisory, ignored at will)
CrawlWall   →  "you are not getting this"       (enforced, logged, verifiable)
```

> [!IMPORTANT]
> CrawlWall is experimental. It is well suited to local testing, demos, and
> shadow-mode trials on production traffic. Review the policy, verifier, and
> ledger behavior before enforcing blocks on real users.

---

## Contents

- [Why block AI crawlers at the edge](#why-block-ai-crawlers-at-the-edge)
- [Quickstart](#quickstart)
- [Supported crawlers](#supported-crawlers)
- [How it works](#how-it-works)
- [Writing policy](#writing-policy)
- [Verifying crawler identity](#verifying-crawler-identity)
- [Actions](#actions)
- [robots.txt generation](#robotstxt-generation)
- [The crawl ledger](#the-crawl-ledger)
- [Signed crawl receipts](#signed-crawl-receipts)
- [Client IP and trusted proxies](#client-ip-and-trusted-proxies)
- [CLI reference](#cli-reference)
- [FAQ](#faq)
- [Project layout](#project-layout)
- [Scope](#scope)
- [Contributing and support](#contributing-and-support)
- [License](#license)

---

## Why block AI crawlers at the edge

AI training crawlers now make up a large share of automated traffic to content
sites. The usual defenses each fall short on their own:

| Approach | Problem |
| --- | --- |
| `robots.txt` | Advisory only. Nothing stops a crawler that ignores it. |
| User-agent blocking | Trivially spoofed. Anyone can send `User-Agent: Googlebot`. |
| Blanket IP bans | Blunt, stale, and they break legitimate search indexing. |
| Application-level checks | Scattered across services and hard to audit. |

CrawlWall answers each of these in one place, at the edge:

| Question | CrawlWall answer |
| --- | --- |
| Is this a known crawler? | Match on `User-Agent` |
| Is it really that crawler? | Verify by reverse DNS or published IP ranges |
| What should happen? | Evaluate CEL rules in priority order |
| What actually happened? | Write a ledger event with a stable event ID |
| Can I charge for it? | `allow_metered` plus signed receipts |

The goal is not cleverness. It is being explicit, inspectable, and replaceable.

## Quickstart

**1. Scaffold a project**

```sh
go run github.com/jolovicdev/crawlwall/cmd/crawlwall@latest init --profile minimal
```

That writes `crawlwall.yaml`, a `Caddyfile`, a `.gitignore`, and an Ed25519 key
pair for receipts.

**2. Build Caddy with the module**

```sh
xcaddy build --with github.com/jolovicdev/crawlwall@latest
```

**3. Point the Caddyfile at your policy**

```caddyfile
{
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
```

**4. Run it and watch a spoofed crawler get turned away**

```sh
caddy run --config ./Caddyfile --adapter caddyfile
```

```sh
curl -A "GPTBot/1.1" http://localhost:8080/archive/report.pdf
```

```
spoofed_bot
```

The request claimed to be GPTBot but did not come from OpenAI's published IP
ranges, so the policy blocked it. A real GPTBot request from a real OpenAI
address would be rate limited or metered instead, depending on your rules.

**5. See what your crawlers are doing**

```sh
crawlwall ledger report --db ./crawlwall.db --since 24h
```

```
Bot        Class        Verified  Requests  Allowed  Blocked  Would block  Metered
GPTBot     ai_training  yes       4821      4102     0        0            719
Googlebot  search       yes       1204      1204     0        0            0
Unknown    unknown      no        9330      812      8518     0            0
```

> [!TIP]
> Start with `site.mode: shadow`. CrawlWall will log every decision it *would*
> have made without touching real traffic. Read the report, then switch to
> `enforce` once the numbers look right.

## Supported crawlers

CrawlWall ships **no fixed blocklist**. You declare the crawlers you care about
and choose how each one is verified. These are the ones people usually configure:

| Crawler | Operator | User-Agent contains | Verify by |
| --- | --- | --- | --- |
| Googlebot | Google | `Googlebot` | reverse DNS (`.googlebot.com`) |
| Bingbot | Microsoft | `bingbot` | reverse DNS (`.search.msn.com`) |
| GPTBot | OpenAI | `GPTBot` | published IP ranges |
| ChatGPT-User | OpenAI | `ChatGPT-User` | published IP ranges |
| OAI-SearchBot | OpenAI | `OAI-SearchBot` | published IP ranges |
| ClaudeBot | Anthropic | `ClaudeBot` | published IP ranges |
| PerplexityBot | Perplexity | `PerplexityBot` | published IP ranges |
| CCBot | Common Crawl | `CCBot` | user agent only |
| Bytespider | ByteDance | `Bytespider` | user agent only |

Matching is a case-insensitive substring of the `User-Agent`. Verification is
what separates a real crawler from anything copying its user agent, so prefer
reverse DNS or IP ranges wherever the operator publishes them.

> [!NOTE]
> robots.txt-only tokens such as `Google-Extended` are advisory and never arrive
> as a distinct fetcher, so they cannot be enforced at the edge. Configure the
> user agents that actually make requests.

## How it works

CrawlWall is four subsystems inside one Caddy handler:

1. **Bot identification** — map a request to a known bot or `unknown`
2. **Verification** — decide whether the claimed identity is trustworthy
3. **Policy evaluation** — run CEL rules against the request context
4. **Audit trail** — write the event and optionally sign a receipt

```mermaid
flowchart LR
    A["HTTP request"] --> B["Bot identifier"]
    B --> C["Verifier"]
    C --> D["Policy engine (CEL)"]
    D --> E["Decision"]
    E --> F["Allow / Block / Rate limit / Allow metered"]
    E --> H["Signed receipt (optional)"]
    H --> G["Ledger writer"]
    F --> I["Upstream app"]
```

Per request:

| Step | What happens |
| --- | --- |
| 1 | Read `User-Agent` and identify the claimed crawler |
| 2 | Verify the request source with that crawler's verifier |
| 3 | Build the policy input: `bot`, `request`, `site`, `sets`, `labels` |
| 4 | Evaluate rules by ascending priority |
| 5 | Enforce the first matching action |
| 6 | If requested, sign a receipt over the stable event ID |
| 7 | Write one ledger record with the decision and receipt metadata |

At startup CrawlWall loads the policy, validates it, compiles every CEL
expression, opens the ledger, prepares verifiers, and loads the receipt signer.
A broken rule fails startup rather than silently failing open at 3am.

### Requirements

- Go matching the version in [`go.mod`](./go.mod)
- [`xcaddy`](https://github.com/caddyserver/xcaddy) to build Caddy with the module
- A ledger DSN when `ledger.enabled` is true: `sqlite://`, `postgres://`, or `mysql://`

Verify the module is present after building:

```sh
caddy list-modules | grep crawlwall
```

Validate before deploying:

```sh
crawlwall policy check --config ./crawlwall.yaml
caddy validate --config ./Caddyfile --adapter caddyfile
```

## Writing policy

Policy is YAML with CEL expressions. The [policy guide](./docs/policy-guide.md)
covers every input, operator, and recipe. The top-level shape:

| Section | Purpose |
| --- | --- |
| `site` | Site identity and enforcement mode |
| `runtime` | Failure behavior and default action |
| `ledger` | Event recording settings |
| `receipts` | Receipt signer configuration |
| `robots` | Generated robots.txt settings |
| `bots` | Known crawler definitions and verifiers |
| `sets` | Reusable policy data |
| `rules` | CEL expressions plus actions |

### Enforcement modes

| Mode | Effect |
| --- | --- |
| `shadow` | Log decisions without blocking or rate limiting |
| `observe` | Alias for `shadow`, kept for older configs |
| `enforce` | Apply block and rate-limit decisions |

Shadow mode evaluates everything, including rate limits, so `ledger report`
shows exactly how many requests a real rollout would have rejected.

### Example rules

Block anything claiming to be a known crawler that fails verification:

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

Let verified search engines through untouched:

```yaml
- id: allow_verified_search
  priority: 100
  when: >
    bot.verified && bot.class == "search"
  action:
    type: allow
```

Charge AI training crawlers for your expensive content:

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

Rate limit them everywhere else:

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

Keep unidentified scrapers out of your archive entirely:

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

Rules run in ascending priority order and the first match wins. If nothing
matches, `runtime.default_action` decides.

### Starter policies

Do not start from a blank file:

| File | Use it when |
| --- | --- |
| [`examples/minimal.yaml`](./examples/minimal.yaml) | You want a readable starter without receipt signing |
| [`examples/full.yaml`](./examples/full.yaml) | You want the full shape with metering and signed receipts |
| [`examples/policy-fixtures.yaml`](./examples/policy-fixtures.yaml) | You want regression tests for policy behavior |

### Testing policy before you ship it

Ask what would happen to a single request:

```sh
crawlwall policy eval --config ./crawlwall.yaml \
  --ua "GPTBot/1.1" --path "/archive/a" --ip 20.125.66.81
```

Run fixture-based regression tests in CI:

```sh
crawlwall policy test --config ./crawlwall.yaml --fixtures ./examples/policy-fixtures.yaml
```

## Verifying crawler identity

Anyone can send `User-Agent: Googlebot`. Verification is what makes the
difference between a policy and a suggestion.

| Verifier | What it does |
| --- | --- |
| `none` | No verification; useful for the `unknown` catch-all |
| `reverse_dns` | Forward-confirmed reverse DNS (FCrDNS) |
| `ip_ranges` | Match the source IP against the operator's published CIDRs |

### reverse_dns

The standard FCrDNS pattern used to verify Googlebot and Bingbot:

1. resolve the remote IP to PTR names
2. require a configured suffix match
3. resolve that hostname back to A/AAAA records
4. require the original IP to be present

```yaml
verify:
  type: reverse_dns
  allowed_suffixes:
    - ".googlebot.com"
    - ".google.com"
```

Results are cached per IP for five minutes, and concurrent lookups for the same
IP share one query, so a crawler burst does not become a DNS flood.

### ip_ranges

For operators that publish their source ranges as JSON:

```yaml
verify:
  type: ip_ranges
  sources:
    - "https://openai.com/gptbot.json"
  refresh: 1h
  stale_action: fail_closed
  max_stale: 0s
```

Ranges are fetched at startup, refreshed in the background, and matched against
the request IP from a warm cache.

| Field | Default | Meaning |
| --- | --- | --- |
| `refresh` | `12h` | How often to refetch the range document |
| `stale_action` | `fail_closed` | Refuse expired ranges after a refresh failure |
| `max_stale` | `0s` | Extra stale-cache lifetime for `use_stale` |

Use `fail_closed` when spoof resistance matters more than crawler availability.
Use `use_stale` with a bounded `max_stale` when temporarily turning away a
legitimate crawler is the worse outcome.

Check cache health at any time:

```sh
crawlwall verifiers status --config ./crawlwall.yaml
```

```
Bot     Type       State  CIDRs  Last fetch            Expires               Stale action
gptbot  ip_ranges  fresh  42     2026-08-15T10:00:00Z  2026-08-15T11:00:00Z  fail_closed
```

> [!IMPORTANT]
> A `GPTBot` request only verifies as `true` if the source IP falls inside
> OpenAI's published ranges at evaluation time. CrawlWall can only know about a
> range rotation after it refreshes the document; a shorter `refresh` narrows
> that window at the cost of more network calls.

## Actions

| Action | Effect |
| --- | --- |
| `allow` | Let the request through |
| `block` | Return an error response immediately |
| `rate_limit` | Allow within a configured rate, then return `429` with `Retry-After` |
| `allow_metered` | Allow the request and record pricing metadata |

`allow_metered` is deliberately narrow. It does not settle payment, issue
invoices, or perform 402 handshakes. It records the metering event and signs a
receipt so billing can be built later without touching the decision engine.

## robots.txt generation

`robots.txt` is the advisory half of the same intent CrawlWall enforces. Keeping
it in a separate hand-edited file is how the two drift apart: the edge blocks
`/archive` while robots.txt still says it is fine, or the reverse.

CrawlWall derives the file from your policy instead. It does not parse rules
back into paths; it asks the compiled engine what it would do for each bot and
each path the policy mentions, so the published file is the enforced answer by
construction.

Generate a snapshot:

```sh
crawlwall robots --config ./crawlwall.yaml --out ./robots.txt
```

Or let the handler serve it from the live policy, which cannot go stale because
a policy change means a reload and a reload re-renders it:

```yaml
robots:
  serve: true
  sitemaps:
    - "https://example.com/sitemap.xml"
```

A policy that blocks unknown crawlers from `/archive`, allows verified search,
and rate limits training bots at 10 rpm produces:

```text
# Generated by crawlwall from the enforced policy. Do not edit by hand.

User-agent: GPTBot
Disallow: /archive
Crawl-delay: 6

User-agent: Googlebot
Disallow:

User-agent: *
Disallow: /
Allow: /public
```

Some things translate exactly, some approximate, and some cannot be said at all:

| Policy | robots.txt |
| --- | --- |
| `block` | `Disallow` |
| `allow`, `allow_metered` | `Allow`, or omitted when already implied |
| `rate_limit` under 60 rpm | `Crawl-delay`, rounded up |
| `rate_limit` at 60 rpm or faster | nothing; sub-second delays are not expressible |
| rules keyed on method, query, IP, or headers | nothing, and a warning |

That last row is the honest part. A rule such as
`request.method == "POST" && request.path.startsWith("/archive")` is still
enforced but cannot appear in robots.txt, so generation reports it:

```text
warning: rule "block_post_to_archive" depends on request.method: robots.txt cannot vary by HTTP method
```

Warnings go to stderr, so `crawlwall robots > robots.txt` stays clean while the
gaps stay visible. When the handler serves the file, they are logged at startup.

Two assumptions are baked into generation. Requests are probed as plain `GET`s,
and a bot with a verifier is treated as verified, because robots.txt speaks to
the honest crawler; an impostor is the edge's problem, not the advisory file's.
A bot with `verify.type: none` is probed unverified, matching runtime.

The handler answers `/robots.txt` before verification and before policy
evaluation. A crawler that cannot read robots.txt assumes everything is
fetchable, so blocking that one path is self-defeating. The fetch is still
recorded under rule `runtime.robots_txt`, so you can see which crawlers
actually read it.

## The crawl ledger

Every decision becomes one row: who asked, what they claimed, whether they
verified, which rule fired, what happened, and whether it was enforced.

```sh
crawlwall ledger report --db ./crawlwall.db --since 24h
crawlwall ledger export --db ./crawlwall.db --format jsonl
crawlwall ledger vacuum --db ./crawlwall.db --older-than 30d
```

### Backends

The ledger runs on **SQLite, PostgreSQL, or MySQL**, selected by the DSN:

```caddyfile
crawlwall {
	policy ./crawlwall.yaml
	ledger sqlite://./crawlwall.db
	# ledger postgres://user:pass@db.internal:5432/crawlwall?sslmode=disable
	# ledger mysql://user:pass@db.internal:3306/crawlwall
}
```

SQLite is the default and needs nothing but a path; it is pure Go, so `xcaddy`
builds stay CGO-free. PostgreSQL and MySQL suit deployments where several edges
write to one ledger. The schema is created on first connect.

There is no ORM here on purpose. The ledger is one table with one insert and
three queries, so a query builder would add a large dependency and reflection on
the write path in exchange for nothing this project needs. The differences that
actually matter — placeholder style, boolean aggregation, timestamp types — live
in [`internal/ledger/dialect.go`](./internal/ledger/dialect.go).

Writes are buffered and committed in batches on a background goroutine, so a
crawler flood never turns the audit trail into a throughput ceiling for the site
it is protecting. If the queue fills, events are dropped and counted rather than
stalling a response, and the drop total is logged. `ledger report` and
`ledger export` flush first, so they always see their own writes.

## Signed crawl receipts

Receipts prove which decision was made for a request. They use Ed25519 and are
intended for metered access and audit, not settlement.

```yaml
receipts:
  enabled: true
  signer:
    type: ed25519
    key_file: ./crawlwall.key
```

Generate keys with `crawlwall init`, or yourself:

```sh
openssl genpkey -algorithm Ed25519 -out crawlwall.key
openssl pkey -in crawlwall.key -pubout -out crawlwall.pub
```

Verify an export against the public key:

```sh
crawlwall receipts verify --file receipts.jsonl --public-key crawlwall.pub
```

> [!WARNING]
> The private key is sensitive and must never be committed. The generated
> [`.gitignore`](./.gitignore) excludes it by default.

## Client IP and trusted proxies

CrawlWall verifies against the client IP Caddy reports. Behind a CDN or load
balancer, configure Caddy's trusted proxies so the real client address is used
rather than your proxy's:

```caddyfile
{
	servers {
		trusted_proxies static 10.0.0.0/8
	}
}
```

Without this, IP-range verification sees your own infrastructure and no crawler
will ever verify.

## CLI reference

| Command | Purpose |
| --- | --- |
| `init` | Scaffold a policy, Caddyfile, and keys |
| `policy check` | Validate and compile the policy |
| `policy eval` | Answer "what would happen to this request?" |
| `policy test` | Run fixture-based policy regression tests |
| `verifiers status` | Show IP-range verifier cache health |
| `robots` | Render robots.txt from the policy |
| `ledger report` | Summarize observed crawler traffic |
| `ledger export` | Dump the event log as JSONL |
| `ledger vacuum` | Delete old events, compacting the file on SQLite |
| `receipts verify` | Validate signed receipt output |
| `version` | Print the CrawlWall version |

## FAQ

**Does this stop AI crawlers that ignore robots.txt?**
Yes. That is the point. robots.txt is a request; CrawlWall returns `403` at the
edge before the request reaches your application.

**Can crawlers get around it by faking a user agent?**
Not for any crawler you verify. A request claiming to be Googlebot is checked
with forward-confirmed reverse DNS, and one claiming to be GPTBot is checked
against OpenAI's published IP ranges. Failing that check is itself something you
can write a rule about.

**Will this hurt my search rankings?**
Only if you configure it to. Verified search crawlers are matched by class, so
`bot.verified && bot.class == "search"` lets Googlebot and Bingbot through while
AI training crawlers are handled separately. Start in shadow mode and read the
report before enforcing.

**Does it work with Nginx or Apache?**
No. CrawlWall is a Caddy module and depends on Caddy's handler chain. The policy
engine and ledger are ordinary Go packages, so another integration is possible,
but none ships today.

**What is the performance cost?**
Bot identification is allocation-free. Verification results are cached (five
minutes for reverse DNS, the configured `refresh` for IP ranges), so the common
path is an in-memory lookup. Ledger writes are batched onto a background
goroutine and never block a response.

**Can I charge AI companies for crawling?**
CrawlWall records metered access and signs a receipt for it. It does not process
payments. The receipt is the artifact you would bill against.

**Does it support blocking by country or ASN?**
Not directly. Caddy handles that upstream, and CrawlWall policy can read request
headers your CDN sets.

**How do I roll this out safely?**
Set `site.mode: shadow`, run for a day, then `crawlwall ledger report`. The
"Would block" column is exactly what `enforce` would have rejected.

## Project layout

```text
cmd/crawlwall/         CLI
docs/                  usage guides
examples/              starter policies
internal/bot/          user-agent matching and bot registry
internal/config/       YAML load and validation
internal/ledger/       ledger interface, batching writer, SQL backends
internal/policy/       CEL environment, compile, evaluate
internal/ratelimit/    in-memory limiter
internal/receipt/      canonical receipts and Ed25519 signing
internal/robots/       robots.txt generation from policy
internal/scaffold/     starter templates for init
internal/verify/       reverse DNS and IP range verifiers
```

The interface worth caring about is the ledger boundary. Request handling
depends only on an `EventWriter` contract: one fully-formed event in, storage
error out. Reporting and export are separate interfaces, so a webhook or
queue-backed writer does not have to pretend it is a database.

## Scope

Included:

- Caddy handler with CEL policy engine
- reverse DNS and IP range crawler verification
- verifier cache status checks
- shadow mode for dry-run policy rollout
- SQLite, PostgreSQL, and MySQL ledgers with retention cleanup
- robots.txt generated from the enforced policy
- signed receipts, local reporting, and export
- policy fixture tests

Deliberately not included:

- payment processing
- dashboards
- distributed quotas
- integrations with other web servers
- policy languages beyond CEL

## Contributing and support

Use [GitHub Issues](https://github.com/jolovicdev/crawlwall/issues) for bugs,
security-relevant behavior questions, and integration reports. Include the
Caddyfile, the CrawlWall policy, the request path, the user agent, and the
observed ledger row where you can.

Run the test suite with:

```sh
go test ./... -race
```

## License

MIT. See [`LICENSE`](./LICENSE).

## Related reading

Cloudflare's pay-per-crawl documentation was useful inspiration for separating
metering from payment. CrawlWall stays much smaller and fully self-hosted:

- [What is pay per crawl?](https://developers.cloudflare.com/ai-crawl-control/features/pay-per-crawl/what-is-pay-per-crawl/)
