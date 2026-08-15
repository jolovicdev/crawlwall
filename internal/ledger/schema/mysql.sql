-- MySQL has no CREATE INDEX IF NOT EXISTS, so the indexes are declared inline:
-- CREATE TABLE IF NOT EXISTS makes the whole statement idempotent. Indexed
-- columns are VARCHAR rather than TEXT because InnoDB caps index key length.
CREATE TABLE IF NOT EXISTS crawl_events (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL,
    ts DATETIME(3) NOT NULL,

    site_id VARCHAR(190) NOT NULL,
    host VARCHAR(255) NOT NULL,
    method VARCHAR(16) NOT NULL,
    path VARCHAR(2048) NOT NULL,
    query TEXT NOT NULL,

    remote_ip VARCHAR(64) NOT NULL,
    user_agent TEXT NOT NULL,

    bot_id VARCHAR(190) NOT NULL,
    bot_name VARCHAR(190) NOT NULL,
    bot_class VARCHAR(64) NOT NULL,
    bot_claimed BOOLEAN NOT NULL,
    bot_verified BOOLEAN NOT NULL,
    verify_type VARCHAR(32) NOT NULL,
    verify_reason VARCHAR(190) NOT NULL,

    rule_id VARCHAR(190) NOT NULL,
    action VARCHAR(64) NOT NULL,
    action_reason VARCHAR(190) NOT NULL,

    status INT NOT NULL,
    bytes_sent BIGINT NOT NULL,
    duration_ms BIGINT NOT NULL,

    price_amount DOUBLE NULL,
    price_currency VARCHAR(16) NULL,
    price_unit VARCHAR(32) NULL,

    receipt_id VARCHAR(64) NULL,
    receipt_signature VARCHAR(255) NULL,

    enforced BOOLEAN NOT NULL DEFAULT FALSE,

    UNIQUE KEY idx_crawl_events_event_id (event_id),
    KEY idx_crawl_events_ts (ts),
    KEY idx_crawl_events_bot_id (bot_id),
    KEY idx_crawl_events_path (path(255)),
    KEY idx_crawl_events_action (action),
    KEY idx_crawl_events_rule (rule_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
