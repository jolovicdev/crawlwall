package ledger

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	// asyncQueueSize bounds how many events may be waiting to be written. Full
	// means the writer cannot keep up; events are dropped rather than allowed
	// to grow memory without limit.
	asyncQueueSize = 4096

	// asyncBatchSize caps how many events go into one transaction.
	asyncBatchSize = 256

	// asyncFlushPeriod bounds how long an event waits before being committed
	// when traffic is too light to fill a batch.
	asyncFlushPeriod = 250 * time.Millisecond

	// asyncWriteTimeout bounds one batch commit so a stuck disk cannot wedge
	// the writer permanently.
	asyncWriteTimeout = 10 * time.Second
)

type batchWriter interface {
	WriteEvents(context.Context, []Event) error
}

// asyncLedger buffers events and commits them in batches on its own goroutine.
// The request path must never wait on a disk write: a crawler flood is exactly
// when the ledger is busiest, and a synchronous insert per request would make
// the audit trail a throughput ceiling for the site it is protecting.
//
// Ordering is preserved (single queue, single writer). Delivery is best effort:
// if the queue fills, events are dropped and counted rather than blocking a
// request or growing memory without bound.
type asyncLedger struct {
	Ledger

	logger   *zap.Logger
	queue    chan queued
	quit     chan struct{}
	stopped  chan struct{}
	quitOnce sync.Once
	dropped  atomic.Int64
}

type queued struct {
	event Event
	// ack marks a flush barrier instead of an event: the writer commits
	// everything queued ahead of it and then closes ack.
	ack chan struct{}
}

func newAsyncLedger(inner Ledger, logger *zap.Logger) *asyncLedger {
	if logger == nil {
		logger = zap.NewNop()
	}

	async := &asyncLedger{
		Ledger:  inner,
		logger:  logger,
		queue:   make(chan queued, asyncQueueSize),
		quit:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go async.run()
	return async
}

func (l *asyncLedger) WriteEvent(_ context.Context, event Event) error {
	if event.EventID == "" {
		event.EventID = newEventID()
	}

	select {
	case l.queue <- queued{event: event}:
	default:
		// The caller is a request handler. Losing an event is bad; stalling the
		// response is worse, so record the loss and move on. The writer logs a
		// running total.
		l.dropped.Add(1)
	}
	return nil
}

// Flush blocks until everything queued before the call has been committed.
func (l *asyncLedger) Flush(ctx context.Context) error {
	ack := make(chan struct{})
	select {
	case l.queue <- queued{ack: ack}:
	case <-l.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case <-ack:
		return nil
	case <-l.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Report, ExportJSONL, and Prune flush first so readers see their own writes;
// without it a report taken right after a request would silently miss it.
func (l *asyncLedger) Report(ctx context.Context, since time.Time) ([]ReportRow, error) {
	if err := l.Flush(ctx); err != nil {
		return nil, err
	}
	return l.Ledger.Report(ctx, since)
}

func (l *asyncLedger) ExportJSONL(ctx context.Context, w io.Writer) error {
	if err := l.Flush(ctx); err != nil {
		return err
	}
	return l.Ledger.ExportJSONL(ctx, w)
}

func (l *asyncLedger) Prune(ctx context.Context, before time.Time) (int64, error) {
	if err := l.Flush(ctx); err != nil {
		return 0, err
	}
	return l.Ledger.Prune(ctx, before)
}

// Close drains the queue and then closes the underlying ledger. The queue is
// never closed, so a request still in flight during a reload drops its event
// instead of panicking on a send to a closed channel.
func (l *asyncLedger) Close() error {
	l.quitOnce.Do(func() { close(l.quit) })
	<-l.stopped
	return l.Ledger.Close()
}

func (l *asyncLedger) run() {
	defer close(l.stopped)

	ticker := time.NewTicker(asyncFlushPeriod)
	defer ticker.Stop()

	batch := make([]Event, 0, asyncBatchSize)
	reported := int64(0)

	for {
		select {
		case item := <-l.queue:
			batch = l.accept(item, batch)
		case <-ticker.C:
			batch = l.commit(batch)
			l.reportDropped(&reported)
		case <-l.quit:
			for {
				select {
				case item := <-l.queue:
					batch = l.accept(item, batch)
				default:
					l.commit(batch)
					l.reportDropped(&reported)
					return
				}
			}
		}
	}
}

func (l *asyncLedger) accept(item queued, batch []Event) []Event {
	if item.ack != nil {
		batch = l.commit(batch)
		close(item.ack)
		return batch
	}

	batch = append(batch, item.event)
	if len(batch) >= asyncBatchSize {
		batch = l.commit(batch)
	}
	return batch
}

// commit writes the batch and returns it emptied for reuse.
func (l *asyncLedger) commit(batch []Event) []Event {
	if len(batch) == 0 {
		return batch
	}

	ctx, cancel := context.WithTimeout(context.Background(), asyncWriteTimeout)
	defer cancel()

	var err error
	if writer, ok := l.Ledger.(batchWriter); ok {
		err = writer.WriteEvents(ctx, batch)
	} else {
		for _, event := range batch {
			if err = l.Ledger.WriteEvent(ctx, event); err != nil {
				break
			}
		}
	}
	if err != nil {
		l.logger.Warn("crawlwall ledger batch write failed",
			zap.Int("events", len(batch)),
			zap.Error(err),
		)
	}

	return batch[:0]
}

// reportDropped logs a running total instead of one line per drop: overload is
// exactly when per-event logging would make things worse.
func (l *asyncLedger) reportDropped(reported *int64) {
	dropped := l.dropped.Load()
	if dropped == *reported {
		return
	}

	l.logger.Warn("crawlwall ledger queue full; events dropped",
		zap.Int64("dropped_since_last", dropped-*reported),
		zap.Int64("dropped_total", dropped),
	)
	*reported = dropped
}
