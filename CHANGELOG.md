# Changelog

All notable changes to CrawlWall are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.0.0]

Multi-backend ledger, robots.txt generation from policy, and a round of
correctness and hot-path fixes.

### Fixed

- A rule whose `when` expression is not a boolean no longer silently never
  matches. Statically non-boolean expressions are rejected at load time, and a
  dyn-typed expression that returns a non-boolean is an evaluation error handled
  by `fail_mode`. Previously a typo such as `when: request.path` disabled a
  block rule without a word.
- Shadow mode evaluates rate limits instead of skipping them, so over-limit
  requests are recorded as `rate_limit_exceeded` and counted under `Would block`
  in `ledger report`. Previously every rate-limited request in a dry run was
  reported as allowed, which defeated the point of shadow mode.
- Verification no longer inherits the request's cancellation, and is bounded by
  a timeout. A client hanging up mid-request used to fail the shared in-flight
  lookup for every other request waiting on it, and reverse DNS had no timeout
  at all, so a slow PTR chain could pin a goroutine indefinitely.
- Ledger writes are detached from the request context. A crawler that hangs up
  mid-response, exactly the traffic worth recording, no longer cancels its own
  audit event.
- IP range documents are read with a size limit rather than fully into memory,
  and the response status is checked before reading.
- Prefixes broad enough to verify most of the internet, such as `0.0.0.0/0`, are
  dropped from range sources instead of trusted.
- A failed range fetch backs off instead of being retried per request, so an
  unreachable source no longer costs every request a full client timeout.
- `match.user_agents` entries must be non-empty. An empty needle is a substring
  of every user agent and would have silently claimed all traffic for that bot.
- Bounded-cache eviction reclaims a batch instead of one entry per insert. Under
  a flood of unique keys, every request past the cap used to pay a full map scan
  while holding the lock.

### Added

- `robots.txt` generated from the enforced policy, removing the drift between
  the advisory file and the rules the edge actually applies. `crawlwall robots`
  renders a snapshot; `robots.serve: true` makes the handler answer
  `/robots.txt` from the live policy. Rules that robots.txt cannot express, such
  as anything keyed on method, query, IP, or headers, are reported rather than
  silently approximated.
- PostgreSQL and MySQL ledger backends alongside SQLite, selected by the DSN
  scheme. Both drivers already ship inside Caddy, so a custom build gains no new
  dependency. See "Ledger backends" in the README.
- Ledger writes are buffered and committed in batches off the request path, so
  the audit trail is no longer a per-request disk write. Overflow is dropped and
  counted rather than stalling a response.
- `Retry-After` on rate-limited responses.

### Changed

- Bot identification precomputes its matchers and folds ASCII case in place, so
  the request path allocates nothing and is roughly 15-30% faster.
- Concurrent reverse DNS lookups for one IP share a single query.
- The cached IP range list is no longer copied on every request.
- `crawlwall ledger` commands accept a full DSN; a bare path still means SQLite.

## [v1.0.0-alpha]

First tagged release.

### Fixed

- Verifier errors no longer return 503 in observe and shadow mode. The
  fail-closed block path applies only in enforce mode, so the dry-run modes
  never affect real traffic.
- Reverse DNS verification treats a missing PTR record as unverified rather
  than a verifier error, and caches it, so spoofed crawlers are handled by
  policy instead of failing closed.
- Each policy decision owns its rate-limit limit, removing a data race and a
  wrong-bucket bug for per-request keys such as request.ip.
- SQLite is opened with WAL, a busy timeout, and synchronous NORMAL so
  concurrent ledger writes are not dropped.
- The rate-limiter map is bounded with idle and least-recently-used eviction.
- A rate-limit limit.key is validated against the known input paths at load
  time, so a typo cannot collapse every request into one shared bucket.
- The ledger records whether a decision was enforced. Reports separate real
  blocks from shadow would-be blocks and no longer count upstream 4xx and 5xx
  responses as blocks.

### Changed

- IP range sources are fetched at startup and refreshed in the background with
  single-flight dedupe, so the request path serves from a warm cache instead of
  fetching inline.
- The module stops background refreshers and closes the ledger on unload, which
  also fixes a ledger handle leak.

### Added

- A `crawlwall version` command and a version field in the startup log.

### Removed

- The unused `bot.signed` policy input.
