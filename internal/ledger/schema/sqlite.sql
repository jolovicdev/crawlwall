CREATE TABLE IF NOT EXISTS crawl_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    ts TEXT NOT NULL,

    site_id TEXT NOT NULL,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT NOT NULL,

    remote_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,

    bot_id TEXT NOT NULL,
    bot_name TEXT NOT NULL,
    bot_class TEXT NOT NULL,
    bot_claimed BOOLEAN NOT NULL,
    bot_verified BOOLEAN NOT NULL,
    verify_type TEXT NOT NULL,
    verify_reason TEXT NOT NULL,

    rule_id TEXT NOT NULL,
    action TEXT NOT NULL,
    action_reason TEXT NOT NULL,

    status INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,

    price_amount REAL,
    price_currency TEXT,
    price_unit TEXT,

    receipt_id TEXT,
    receipt_signature TEXT,

    enforced BOOLEAN NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_crawl_events_ts ON crawl_events(ts);
CREATE INDEX IF NOT EXISTS idx_crawl_events_bot_id ON crawl_events(bot_id);
CREATE INDEX IF NOT EXISTS idx_crawl_events_path ON crawl_events(path);
CREATE INDEX IF NOT EXISTS idx_crawl_events_action ON crawl_events(action);
CREATE INDEX IF NOT EXISTS idx_crawl_events_rule ON crawl_events(rule_id);
