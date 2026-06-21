package ledger

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSQLiteLedgerPruneDeletesOldEvents(t *testing.T) {
	ctx := context.Background()
	led, err := Open("sqlite://"+filepath.Join(t.TempDir(), "crawlwall.db"), true)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer led.Close()

	oldEvent := testEvent("old", time.Now().Add(-48*time.Hour))
	newEvent := testEvent("new", time.Now())
	if err := led.WriteEvent(ctx, oldEvent); err != nil {
		t.Fatalf("WriteEvent(old) error = %v", err)
	}
	if err := led.WriteEvent(ctx, newEvent); err != nil {
		t.Fatalf("WriteEvent(new) error = %v", err)
	}

	deleted, err := led.Prune(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}
	if deleted != 1 {
		t.Fatalf("Prune() deleted = %d, want 1", deleted)
	}

	var out bytes.Buffer
	if err := led.ExportJSONL(ctx, &out); err != nil {
		t.Fatalf("ExportJSONL() error = %v", err)
	}
	exported := out.String()
	if strings.Contains(exported, `"EventID":"old"`) {
		t.Fatalf("export still contains old event: %s", exported)
	}
	if !strings.Contains(exported, `"EventID":"new"`) {
		t.Fatalf("export does not contain new event: %s", exported)
	}
}

func TestSQLiteLedgerConcurrentWritesAllPersist(t *testing.T) {
	ctx := context.Background()
	led, err := Open("sqlite://"+filepath.Join(t.TempDir(), "crawlwall.db"), true)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer led.Close()

	const writers = 32
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			event := testEvent(fmt.Sprintf("evt-%d", n), time.Now())
			if err := led.WriteEvent(ctx, event); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent WriteEvent error = %v", err)
	}

	var out bytes.Buffer
	if err := led.ExportJSONL(ctx, &out); err != nil {
		t.Fatalf("ExportJSONL() error = %v", err)
	}
	lines := strings.Count(strings.TrimSpace(out.String()), "\n") + 1
	if lines != writers {
		t.Fatalf("persisted events = %d, want %d", lines, writers)
	}
}

func TestSQLiteLedgerReportSeparatesEnforcedFromShadow(t *testing.T) {
	ctx := context.Background()
	led, err := Open("sqlite://"+filepath.Join(t.TempDir(), "crawlwall.db"), true)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer led.Close()

	now := time.Now()

	enforcedBlock := testEvent("enforced", now)
	enforcedBlock.Action = "block"
	enforcedBlock.Status = 403
	enforcedBlock.Enforced = true

	shadowBlock := testEvent("shadow", now)
	shadowBlock.Action = "block"
	shadowBlock.Status = 200
	shadowBlock.Enforced = false

	allowUpstreamError := testEvent("allow", now)
	allowUpstreamError.Action = "allow"
	allowUpstreamError.Status = 500
	allowUpstreamError.Enforced = false

	for _, event := range []Event{enforcedBlock, shadowBlock, allowUpstreamError} {
		if err := led.WriteEvent(ctx, event); err != nil {
			t.Fatalf("WriteEvent(%s) error = %v", event.EventID, err)
		}
	}

	rows, err := led.Report(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Report() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.Blocked != 1 {
		t.Fatalf("blocked = %d, want 1 (only the enforced block)", row.Blocked)
	}
	if row.WouldBlock != 1 {
		t.Fatalf("would_block = %d, want 1 (the shadow block)", row.WouldBlock)
	}
	if row.Allowed != 1 {
		t.Fatalf("allowed = %d, want 1 (an upstream 500 is not a CrawlWall block)", row.Allowed)
	}
}

func TestSQLiteLedgerMigratesEnforcedColumn(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "crawlwall.db")

	led, err := Open("sqlite://"+path, true)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := led.WriteEvent(ctx, testEvent("seed", time.Now())); err != nil {
		t.Fatalf("WriteEvent(seed) error = %v", err)
	}
	if err := led.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Simulate a database created before the enforced column existed.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	if _, err := raw.Exec(`ALTER TABLE crawl_events DROP COLUMN enforced`); err != nil {
		t.Fatalf("drop enforced column: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("raw Close() error = %v", err)
	}

	// Reopening should re-add the column via migration and stay usable.
	led2, err := Open("sqlite://"+path, true)
	if err != nil {
		t.Fatalf("reopen Open() error = %v", err)
	}
	defer led2.Close()
	if _, err := led2.Report(ctx, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("Report() after migration error = %v", err)
	}
	if err := led2.WriteEvent(ctx, testEvent("after", time.Now())); err != nil {
		t.Fatalf("WriteEvent(after) error = %v", err)
	}
}

func testEvent(id string, ts time.Time) Event {
	return Event{
		EventID:      id,
		TS:           ts,
		SiteID:       "test-site",
		Host:         "example.com",
		Method:       "GET",
		Path:         "/",
		RemoteIP:     "127.0.0.1",
		UserAgent:    "curl/8.0",
		BotID:        "unknown",
		BotName:      "Unknown",
		BotClass:     "unknown",
		VerifyType:   "none",
		VerifyReason: "verification_not_required",
		RuleID:       "runtime.default_action",
		Action:       "allow",
		Status:       200,
	}
}
