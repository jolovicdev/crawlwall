package ledger

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"time"

	_ "github.com/go-sql-driver/mysql" // mysql:// ledgers
	_ "github.com/jackc/pgx/v5/stdlib" // postgres:// ledgers
	_ "modernc.org/sqlite"             // sqlite:// ledgers, pure Go so xcaddy builds stay cgo-free

	"github.com/jolovicdev/crawlwall/internal/receipt"
)

// sqlLedger is the storage backend for every supported database. Statements are
// written once with ? placeholders and adapted by the dialect.
type sqlLedger struct {
	db      *sql.DB
	dialect dialect
}

func openSQL(dsn string) (Ledger, error) {
	dia, err := openDialect(dsn)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open(dia.driver, dia.dsn)
	if err != nil {
		return nil, err
	}
	if dia.maxOpenConns > 0 {
		db.SetMaxOpenConns(dia.maxOpenConns)
		db.SetMaxIdleConns(dia.maxOpenConns)
	}
	// Network backends drop idle connections; recycling before they do avoids
	// losing a batch to a server-side timeout.
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := dia.applySchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize %s schema: %w", dia.name, err)
	}
	if dia.name == "sqlite" {
		// Only SQLite has deployed databases predating event_id and enforced.
		if err := ensureSQLiteMigrations(db); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate sqlite schema: %w", err)
		}
	}

	return &sqlLedger{db: db, dialect: dia}, nil
}

const insertEventSQL = `
	INSERT INTO crawl_events (
		event_id, ts, site_id, host, method, path, query,
		remote_ip, user_agent,
		bot_id, bot_name, bot_class, bot_claimed, bot_verified, verify_type, verify_reason,
		rule_id, action, action_reason,
		status, bytes_sent, duration_ms,
		price_amount, price_currency, price_unit,
		receipt_id, receipt_signature, enforced
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

const selectEventSQL = `
	SELECT
		id, event_id, ts, site_id, host, method, path, query,
		remote_ip, user_agent,
		bot_id, bot_name, bot_class, bot_claimed, bot_verified, verify_type, verify_reason,
		rule_id, action, action_reason,
		status, bytes_sent, duration_ms,
		price_amount, price_currency, price_unit,
		receipt_id, receipt_signature, enforced
	FROM crawl_events
	ORDER BY id ASC
`

func (l *sqlLedger) insertArgs(event Event) []any {
	if event.EventID == "" {
		event.EventID = newEventID()
	}
	return []any{
		event.EventID,
		l.dialect.timeArg(event.TS),
		event.SiteID,
		event.Host,
		event.Method,
		event.Path,
		event.Query,
		event.RemoteIP,
		event.UserAgent,
		event.BotID,
		event.BotName,
		event.BotClass,
		event.BotClaimed,
		event.BotVerified,
		event.VerifyType,
		event.VerifyReason,
		event.RuleID,
		event.Action,
		event.ActionReason,
		event.Status,
		event.BytesSent,
		event.DurationMS,
		event.PriceAmount,
		event.PriceCurrency,
		event.PriceUnit,
		event.ReceiptID,
		event.ReceiptSignature,
		event.Enforced,
	}
}

func (l *sqlLedger) WriteEvent(ctx context.Context, event Event) error {
	_, err := l.db.ExecContext(ctx, l.dialect.rebind(insertEventSQL), l.insertArgs(event)...)
	return err
}

// WriteEvents inserts a batch in one transaction. Every supported backend
// commits per transaction, so batching is what lets the ledger keep up with
// crawler-scale traffic instead of paying a commit per request.
func (l *sqlLedger) WriteEvents(ctx context.Context, events []Event) error {
	if len(events) == 1 {
		return l.WriteEvent(ctx, events[0])
	}

	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, l.dialect.rebind(insertEventSQL))
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, event := range events {
		if _, err := stmt.ExecContext(ctx, l.insertArgs(event)...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Flush satisfies Ledger; writes are durable once WriteEvent returns. The
// buffering that needs flushing lives in asyncLedger.
func (l *sqlLedger) Flush(context.Context) error { return nil }

func (l *sqlLedger) Report(ctx context.Context, since time.Time) ([]ReportRow, error) {
	// FALSE is a valid boolean literal on every supported engine (SQLite and
	// MySQL evaluate it as 0), so only the aggregate differs per dialect.
	query := fmt.Sprintf(`
		SELECT
			bot_id,
			bot_name,
			bot_class,
			%s AS verified,
			COUNT(*) AS requests,
			SUM(CASE WHEN action IN ('allow', 'rate_limit') AND enforced = FALSE THEN 1 ELSE 0 END) AS allowed,
			SUM(CASE WHEN enforced <> FALSE THEN 1 ELSE 0 END) AS blocked,
			SUM(CASE WHEN action IN ('block', 'rate_limit_exceeded') AND enforced = FALSE THEN 1 ELSE 0 END) AS would_block,
			SUM(CASE WHEN action = 'allow_metered' THEN 1 ELSE 0 END) AS metered
		FROM crawl_events
		WHERE ts >= ?
		GROUP BY bot_id, bot_name, bot_class
		ORDER BY requests DESC, bot_id ASC
	`, l.dialect.boolOr)

	rows, err := l.db.QueryContext(ctx, l.dialect.rebind(query), l.dialect.timeArg(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var report []ReportRow
	for rows.Next() {
		row, err := scanReportRow(rows)
		if err != nil {
			return nil, err
		}
		report = append(report, row)
	}
	return report, rows.Err()
}

// scanReportRow reads the aggregates through any because SUM() is bigint on
// PostgreSQL and SQLite but DECIMAL on MySQL, and bool_or returns a real
// boolean only on PostgreSQL.
func scanReportRow(rows *sql.Rows) (ReportRow, error) {
	var row ReportRow
	var verified, requests, allowed, blocked, wouldBlock, metered any

	if err := rows.Scan(&row.BotID, &row.BotName, &row.Class, &verified,
		&requests, &allowed, &blocked, &wouldBlock, &metered); err != nil {
		return ReportRow{}, err
	}

	counts := []struct {
		raw any
		out *int64
	}{
		{requests, &row.Requests},
		{allowed, &row.Allowed},
		{blocked, &row.Blocked},
		{wouldBlock, &row.WouldBlock},
		{metered, &row.Metered},
	}
	for _, count := range counts {
		value, err := asInt64(count.raw)
		if err != nil {
			return ReportRow{}, err
		}
		*count.out = value
	}

	flag, err := asInt64(verified)
	if err != nil {
		return ReportRow{}, err
	}
	row.Verified = flag != 0

	return row, nil
}

func (l *sqlLedger) ExportJSONL(ctx context.Context, w io.Writer) error {
	rows, err := l.db.QueryContext(ctx, selectEventSQL)
	if err != nil {
		return err
	}
	defer rows.Close()

	encoder := json.NewEncoder(w)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return err
		}

		record := ExportRecord{Event: event}
		if event.ReceiptSignature != "" {
			record.Receipt = &receipt.Envelope{
				ReceiptID: event.ReceiptID,
				Payload:   event.ReceiptPayload(),
				Signature: event.ReceiptSignature,
			}
		}

		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (l *sqlLedger) Prune(ctx context.Context, before time.Time) (int64, error) {
	result, err := l.db.ExecContext(ctx,
		l.dialect.rebind(`DELETE FROM crawl_events WHERE ts < ?`),
		l.dialect.timeArg(before))
	if err != nil {
		return 0, err
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	// Reclaiming space is SQLite-specific. VACUUM there rewrites the file and
	// takes an exclusive lock; PostgreSQL and MySQL reuse freed pages on their
	// own, and a manual VACUUM would need privileges crawlwall should not
	// assume it has.
	if l.dialect.name == "sqlite" {
		if _, err := l.db.ExecContext(ctx, `VACUUM`); err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

func (l *sqlLedger) Close() error {
	return l.db.Close()
}

func scanEvent(scanner interface{ Scan(dest ...any) error }) (Event, error) {
	var event Event
	var ts any
	var priceAmount sql.NullFloat64
	var priceCurrency sql.NullString
	var priceUnit sql.NullString
	var receiptID sql.NullString
	var receiptSignature sql.NullString

	err := scanner.Scan(
		&event.ID,
		&event.EventID,
		&ts,
		&event.SiteID,
		&event.Host,
		&event.Method,
		&event.Path,
		&event.Query,
		&event.RemoteIP,
		&event.UserAgent,
		&event.BotID,
		&event.BotName,
		&event.BotClass,
		&event.BotClaimed,
		&event.BotVerified,
		&event.VerifyType,
		&event.VerifyReason,
		&event.RuleID,
		&event.Action,
		&event.ActionReason,
		&event.Status,
		&event.BytesSent,
		&event.DurationMS,
		&priceAmount,
		&priceCurrency,
		&priceUnit,
		&receiptID,
		&receiptSignature,
		&event.Enforced,
	)
	if err != nil {
		return Event{}, err
	}

	parsedTS, err := parseTimestamp(ts)
	if err != nil {
		return Event{}, err
	}
	event.TS = parsedTS

	if priceAmount.Valid {
		event.PriceAmount = &priceAmount.Float64
	}
	if priceCurrency.Valid {
		event.PriceCurrency = &priceCurrency.String
	}
	if priceUnit.Valid {
		event.PriceUnit = &priceUnit.String
	}
	event.ReceiptID = receiptID.String
	event.ReceiptSignature = receiptSignature.String

	return event, nil
}

func ensureSQLiteMigrations(db *sql.DB) error {
	hasEventID, err := sqliteColumnExists(db, "crawl_events", "event_id")
	if err != nil {
		return err
	}
	if !hasEventID {
		if _, err := db.Exec(`ALTER TABLE crawl_events ADD COLUMN event_id TEXT`); err != nil {
			return err
		}
		if _, err := db.Exec(`UPDATE crawl_events SET event_id = 'legacy-' || id WHERE event_id IS NULL OR event_id = ''`); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_crawl_events_event_id ON crawl_events(event_id)`); err != nil {
		return err
	}

	hasEnforced, err := sqliteColumnExists(db, "crawl_events", "enforced")
	if err != nil {
		return err
	}
	if !hasEnforced {
		if _, err := db.Exec(`ALTER TABLE crawl_events ADD COLUMN enforced BOOLEAN NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	return nil
}

func sqliteColumnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
