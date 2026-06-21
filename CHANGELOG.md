# Changelog

All notable changes to CrawlWall are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
