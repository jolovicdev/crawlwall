package ledger

import (
	"bytes"
	"context"
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
