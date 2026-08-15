package ledger

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestAsyncLedgerBatchesAndFlushes(t *testing.T) {
	inner := &recordingLedger{}
	async := newAsyncLedger(inner, zap.NewNop())
	defer func() { _ = async.Close() }()

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := async.WriteEvent(ctx, Event{SiteID: "s"}); err != nil {
			t.Fatalf("WriteEvent() error = %v", err)
		}
	}

	if err := async.Flush(ctx); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if got := inner.eventCount(); got != 10 {
		t.Fatalf("inner events = %d, want 10", got)
	}
	// Ten events queued back to back must not cost ten commits.
	if got := inner.batchCount(); got > 3 {
		t.Fatalf("inner batches = %d, want the writes to be batched", got)
	}
}

func TestAsyncLedgerAssignsEventIDs(t *testing.T) {
	inner := &recordingLedger{}
	async := newAsyncLedger(inner, zap.NewNop())
	defer func() { _ = async.Close() }()

	if err := async.WriteEvent(context.Background(), Event{SiteID: "s"}); err != nil {
		t.Fatalf("WriteEvent() error = %v", err)
	}
	if err := async.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	inner.mu.Lock()
	defer inner.mu.Unlock()
	if inner.events[0].EventID == "" {
		t.Fatalf("event ID should be assigned before queueing, so drops are still identifiable")
	}
}

func TestAsyncLedgerDropsInsteadOfBlockingWhenFull(t *testing.T) {
	// A ledger that never returns keeps the writer busy, so the queue fills.
	blocked := make(chan struct{})
	inner := &recordingLedger{block: blocked}
	async := newAsyncLedger(inner, zap.NewNop())
	defer func() {
		close(blocked)
		_ = async.Close()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < asyncQueueSize*2; i++ {
			_ = async.WriteEvent(context.Background(), Event{SiteID: "s"})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("WriteEvent blocked; the request path must never wait on the ledger")
	}

	if async.dropped.Load() == 0 {
		t.Fatalf("dropped = 0, want the overflow to be counted")
	}
}

func TestAsyncLedgerCloseIsIdempotent(t *testing.T) {
	async := newAsyncLedger(&recordingLedger{}, zap.NewNop())
	if err := async.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := async.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	// A request still in flight during a reload must not panic on a closed queue.
	if err := async.WriteEvent(context.Background(), Event{SiteID: "s"}); err != nil {
		t.Fatalf("WriteEvent() after Close error = %v", err)
	}
}

type recordingLedger struct {
	mu      sync.Mutex
	events  []Event
	batches int
	block   chan struct{}
}

func (l *recordingLedger) WriteEvent(ctx context.Context, event Event) error {
	return l.WriteEvents(ctx, []Event{event})
}

func (l *recordingLedger) WriteEvents(_ context.Context, events []Event) error {
	if l.block != nil {
		<-l.block
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, events...)
	l.batches++
	return nil
}

func (l *recordingLedger) eventCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

func (l *recordingLedger) batchCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.batches
}

func (l *recordingLedger) Flush(context.Context) error { return nil }
func (l *recordingLedger) Close() error                { return nil }
func (l *recordingLedger) Report(context.Context, time.Time) ([]ReportRow, error) {
	return nil, errors.New("not implemented")
}
func (l *recordingLedger) ExportJSONL(context.Context, io.Writer) error { return nil }
func (l *recordingLedger) Prune(context.Context, time.Time) (int64, error) {
	return 0, nil
}
