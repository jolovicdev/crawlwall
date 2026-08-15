package ledger

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestBackendsRoundTrip runs the same write/report/export/prune cycle against
// every backend the DSN environment provides. SQLite always runs; PostgreSQL
// and MySQL run when CRAWLWALL_TEST_POSTGRES_DSN / CRAWLWALL_TEST_MYSQL_DSN
// point at a live server, which is how the dialect differences (placeholders,
// bool_or, DECIMAL aggregates, native timestamps) get exercised for real.
func TestBackendsRoundTrip(t *testing.T) {
	for _, backend := range testBackends(t) {
		t.Run(backend.name, func(t *testing.T) {
			ctx := context.Background()
			led, err := Open(backend.dsn, true, zap.NewNop())
			if err != nil {
				t.Fatalf("Open(%s) error = %v", backend.name, err)
			}
			t.Cleanup(func() { _ = led.Close() })

			now := time.Now().UTC().Truncate(time.Second)
			events := []Event{
				newTestEvent("evt_allow", now, "googlebot", "allow", false),
				newTestEvent("evt_block", now, "gptbot", "block", true),
				newTestEvent("evt_shadow", now, "gptbot", "rate_limit_exceeded", false),
				meteredTestEvent("evt_metered", now, "claudebot"),
			}
			for _, event := range events {
				if err := led.WriteEvent(ctx, event); err != nil {
					t.Fatalf("WriteEvent() error = %v", err)
				}
			}
			if err := led.Flush(ctx); err != nil {
				t.Fatalf("Flush() error = %v", err)
			}

			report, err := led.Report(ctx, now.Add(-time.Hour))
			if err != nil {
				t.Fatalf("Report() error = %v", err)
			}

			byBot := map[string]ReportRow{}
			for _, row := range report {
				byBot[row.BotID] = row
			}
			if got := byBot["gptbot"]; got.Requests != 2 || got.Blocked != 1 || got.WouldBlock != 1 {
				t.Fatalf("gptbot row = %+v, want requests 2, blocked 1, would_block 1", got)
			}
			if got := byBot["googlebot"]; got.Allowed != 1 || !got.Verified {
				t.Fatalf("googlebot row = %+v, want allowed 1 and verified", got)
			}
			if got := byBot["claudebot"]; got.Metered != 1 {
				t.Fatalf("claudebot row = %+v, want metered 1", got)
			}

			var exported bytes.Buffer
			if err := led.ExportJSONL(ctx, &exported); err != nil {
				t.Fatalf("ExportJSONL() error = %v", err)
			}
			lines := strings.Split(strings.TrimSpace(exported.String()), "\n")
			if len(lines) != len(events) {
				t.Fatalf("exported %d lines, want %d", len(lines), len(events))
			}

			record, err := ParseExportLine([]byte(lines[0]))
			if err != nil {
				t.Fatalf("ParseExportLine() error = %v", err)
			}
			if !record.Event.TS.Equal(now) {
				t.Fatalf("round-tripped ts = %s, want %s", record.Event.TS, now)
			}
			if record.Event.EventID != "evt_allow" {
				t.Fatalf("round-tripped event_id = %q, want evt_allow", record.Event.EventID)
			}

			// The metered event carries a price; make sure the nullable numeric
			// columns survive the round trip on every backend.
			last, err := ParseExportLine([]byte(lines[len(lines)-1]))
			if err != nil {
				t.Fatalf("ParseExportLine() error = %v", err)
			}
			if last.Event.PriceAmount == nil || *last.Event.PriceAmount != 0.002 {
				t.Fatalf("round-tripped price = %v, want 0.002", last.Event.PriceAmount)
			}

			deleted, err := led.Prune(ctx, now.Add(time.Hour))
			if err != nil {
				t.Fatalf("Prune() error = %v", err)
			}
			if deleted != int64(len(events)) {
				t.Fatalf("Prune() deleted %d, want %d", deleted, len(events))
			}
		})
	}
}

func TestOpenRejectsUnknownScheme(t *testing.T) {
	if _, err := Open("mongodb://localhost/crawlwall", true, zap.NewNop()); err == nil {
		t.Fatalf("Open() error = nil, want unsupported scheme error")
	}
	if _, err := Open("./crawlwall.db", true, zap.NewNop()); err == nil {
		t.Fatalf("Open() error = nil, want missing scheme error")
	}
}

func TestMySQLConnStringConvertsURL(t *testing.T) {
	got, err := mysqlConnString("mysql://cw:secret@db.internal/crawlwall")
	if err != nil {
		t.Fatalf("mysqlConnString() error = %v", err)
	}
	if !strings.HasPrefix(got, "cw:secret@tcp(db.internal:3306)/crawlwall?") {
		t.Fatalf("mysqlConnString() = %q, want tcp form with default port", got)
	}
	if !strings.Contains(got, "parseTime=true") {
		t.Fatalf("mysqlConnString() = %q, want parseTime enabled", got)
	}
}

func TestRebindNumbersPlaceholders(t *testing.T) {
	numbered := dialect{numberedParams: true}
	if got := numbered.rebind("INSERT INTO t VALUES (?, ?, ?)"); got != "INSERT INTO t VALUES ($1, $2, $3)" {
		t.Fatalf("rebind() = %q", got)
	}
	if got := (dialect{}).rebind("SELECT ?"); got != "SELECT ?" {
		t.Fatalf("rebind() should leave ? alone for question-mark dialects, got %q", got)
	}
}

type testBackend struct {
	name string
	dsn  string
}

func testBackends(t *testing.T) []testBackend {
	t.Helper()

	backends := []testBackend{{
		name: "sqlite",
		dsn:  "sqlite://" + filepath.Join(t.TempDir(), "crawlwall.db"),
	}}

	for _, candidate := range []testBackend{
		{name: "postgres", dsn: os.Getenv("CRAWLWALL_TEST_POSTGRES_DSN")},
		{name: "mysql", dsn: os.Getenv("CRAWLWALL_TEST_MYSQL_DSN")},
	} {
		if candidate.dsn != "" {
			backends = append(backends, candidate)
		}
	}
	return backends
}

func newTestEvent(id string, ts time.Time, botID, action string, enforced bool) Event {
	return Event{
		EventID:      id,
		TS:           ts,
		SiteID:       "test-site",
		Host:         "example.test",
		Method:       "GET",
		Path:         "/archive",
		Query:        "page=1",
		RemoteIP:     "203.0.113.7",
		UserAgent:    "TestBot/1.0",
		BotID:        botID,
		BotName:      botID,
		BotClass:     "ai_training",
		BotClaimed:   true,
		BotVerified:  true,
		VerifyType:   "ip_ranges",
		VerifyReason: "ip_range_match",
		RuleID:       "rule_" + action,
		Action:       action,
		ActionReason: action,
		Status:       200,
		BytesSent:    1234,
		DurationMS:   7,
		Enforced:     enforced,
	}
}

func meteredTestEvent(id string, ts time.Time, botID string) Event {
	event := newTestEvent(id, ts, botID, "allow_metered", false)
	event.PriceAmount = ptrFloat(0.002)
	event.PriceCurrency = ptrString("USD")
	event.PriceUnit = ptrString("request")
	return event
}
