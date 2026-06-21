package ledger

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/jolovicdev/crawlwall/internal/receipt"
)

//go:embed schema.sql
var sqliteSchema string

type sqliteLedger struct {
	db *sql.DB
}

func openSQLite(dsn string) (Ledger, error) {
	if !strings.HasPrefix(dsn, "sqlite://") {
		return nil, fmt.Errorf("unsupported ledger DSN %q", dsn)
	}

	path := strings.TrimPrefix(dsn, "sqlite://")
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("sqlite ledger path is required")
	}

	db, err := sql.Open("sqlite", sqliteConnString(path))
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(sqliteSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize sqlite schema: %w", err)
	}
	if err := ensureSQLiteMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate sqlite schema: %w", err)
	}

	return &sqliteLedger{db: db}, nil
}

// sqliteConnString adds per-connection pragmas. WAL plus a busy timeout lets
// the request-path writers wait briefly for the lock instead of dropping events
// with SQLITE_BUSY under concurrency.
func sqliteConnString(path string) string {
	pragmas := []string{
		"_pragma=busy_timeout(5000)",
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(NORMAL)",
		"_pragma=foreign_keys(ON)",
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return path + separator + strings.Join(pragmas, "&")
}

func (l *sqliteLedger) WriteEvent(ctx context.Context, event Event) error {
	if event.EventID == "" {
		event.EventID = newEventID()
	}

	_, err := l.db.ExecContext(ctx, `
		INSERT INTO crawl_events (
			event_id, ts, site_id, host, method, path, query,
			remote_ip, user_agent,
			bot_id, bot_name, bot_class, bot_claimed, bot_verified, verify_type, verify_reason,
			rule_id, action, action_reason,
			status, bytes_sent, duration_ms,
			price_amount, price_currency, price_unit,
			receipt_id, receipt_signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		event.EventID,
		event.TS.Format(time.RFC3339),
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
	)
	return err
}

func (l *sqliteLedger) Report(ctx context.Context, since time.Time) ([]ReportRow, error) {
	rows, err := l.db.QueryContext(ctx, `
		SELECT
			bot_id,
			bot_name,
			bot_class,
			MAX(bot_verified) AS verified,
			COUNT(*) AS requests,
			SUM(CASE WHEN action IN ('allow', 'rate_limit') AND status < 400 THEN 1 ELSE 0 END) AS allowed,
			SUM(CASE WHEN action IN ('block', 'rate_limit_exceeded') OR status >= 400 THEN 1 ELSE 0 END) AS blocked,
			SUM(CASE WHEN action = 'allow_metered' THEN 1 ELSE 0 END) AS metered
		FROM crawl_events
		WHERE ts >= ?
		GROUP BY bot_id, bot_name, bot_class
		ORDER BY requests DESC, bot_id ASC
	`, since.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var report []ReportRow
	for rows.Next() {
		var row ReportRow
		if err := rows.Scan(&row.BotID, &row.BotName, &row.Class, &row.Verified, &row.Requests, &row.Allowed, &row.Blocked, &row.Metered); err != nil {
			return nil, err
		}
		report = append(report, row)
	}
	return report, rows.Err()
}

func (l *sqliteLedger) ExportJSONL(ctx context.Context, w io.Writer) error {
	rows, err := l.db.QueryContext(ctx, `
		SELECT
			id, event_id, ts, site_id, host, method, path, query,
			remote_ip, user_agent,
			bot_id, bot_name, bot_class, bot_claimed, bot_verified, verify_type, verify_reason,
			rule_id, action, action_reason,
			status, bytes_sent, duration_ms,
			price_amount, price_currency, price_unit,
			receipt_id, receipt_signature
		FROM crawl_events
		ORDER BY id ASC
	`)
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

func (l *sqliteLedger) Prune(ctx context.Context, before time.Time) (int64, error) {
	result, err := l.db.ExecContext(ctx, `
		DELETE FROM crawl_events
		WHERE ts < ?
	`, before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}

	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	if _, err := l.db.ExecContext(ctx, `VACUUM`); err != nil {
		return deleted, err
	}
	return deleted, nil
}

func (l *sqliteLedger) Close() error {
	return l.db.Close()
}

func scanEvent(scanner interface{ Scan(dest ...any) error }) (Event, error) {
	var event Event
	var ts string
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
	)
	if err != nil {
		return Event{}, err
	}

	parsedTS, err := time.Parse(time.RFC3339, ts)
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
	if receiptID.Valid {
		event.ReceiptID = receiptID.String
	}
	if receiptSignature.Valid {
		event.ReceiptSignature = receiptSignature.String
	}

	return event, nil
}

func ensureSQLiteMigrations(db *sql.DB) error {
	hasEventID, err := sqliteColumnExists(db, "crawl_events", "event_id")
	if err != nil {
		return err
	}
	if hasEventID {
		_, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_crawl_events_event_id ON crawl_events(event_id)`)
		return err
	}

	if _, err := db.Exec(`
		ALTER TABLE crawl_events ADD COLUMN event_id TEXT;
		UPDATE crawl_events SET event_id = 'legacy-' || id WHERE event_id IS NULL OR event_id = '';
		CREATE UNIQUE INDEX IF NOT EXISTS idx_crawl_events_event_id ON crawl_events(event_id);
	`); err != nil {
		return err
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
