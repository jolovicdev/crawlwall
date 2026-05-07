package ledger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/jolovicdev/crawlwall/internal/bot"
	"github.com/jolovicdev/crawlwall/internal/config"
	"github.com/jolovicdev/crawlwall/internal/policy"
	"github.com/jolovicdev/crawlwall/internal/receipt"
	"github.com/jolovicdev/crawlwall/internal/verify"
)

type EventWriter interface {
	WriteEvent(context.Context, Event) error
	Close() error
}

type Reporter interface {
	Report(context.Context, time.Time) ([]ReportRow, error)
}

type Exporter interface {
	ExportJSONL(context.Context, io.Writer) error
}

type Pruner interface {
	Prune(context.Context, time.Time) (int64, error)
}

type Ledger interface {
	EventWriter
	Reporter
	Exporter
	Pruner
}

type Event struct {
	ID               int64
	EventID          string
	TS               time.Time
	SiteID           string
	Host             string
	Method           string
	Path             string
	Query            string
	RemoteIP         string
	UserAgent        string
	BotID            string
	BotName          string
	BotClass         string
	BotClaimed       bool
	BotVerified      bool
	VerifyType       string
	VerifyReason     string
	RuleID           string
	Action           string
	ActionReason     string
	Status           int
	BytesSent        int64
	DurationMS       int64
	PriceAmount      *float64
	PriceCurrency    *string
	PriceUnit        *string
	ReceiptID        string
	ReceiptSignature string
	ReceiptRequested bool
}

type ReportRow struct {
	BotID    string
	BotName  string
	Class    string
	Verified bool
	Requests int64
	Allowed  int64
	Blocked  int64
	Metered  int64
}

type ExportRecord struct {
	Event   Event             `json:"event"`
	Receipt *receipt.Envelope `json:"receipt,omitempty"`
}

func EventFromRequest(start time.Time, r *http.Request, remoteIP net.IP, identified bot.Identified, verification verify.Result, decision policy.Decision, siteID string) Event {
	event := Event{
		EventID:          newEventID(),
		TS:               start.UTC(),
		SiteID:           siteID,
		Host:             r.Host,
		Method:           r.Method,
		Path:             r.URL.Path,
		Query:            r.URL.RawQuery,
		RemoteIP:         remoteIP.String(),
		UserAgent:        r.UserAgent(),
		BotID:            identified.ID,
		BotName:          identified.Name,
		BotClass:         identified.Class,
		BotClaimed:       identified.Claimed,
		BotVerified:      verification.Verified,
		VerifyType:       verification.Type,
		VerifyReason:     verification.Reason,
		RuleID:           decision.RuleID,
		Action:           string(decision.Action.Type),
		ActionReason:     decision.Action.Reason,
		ReceiptRequested: decision.Audit.Receipt,
	}

	if decision.Action.Price != nil {
		event.PriceAmount = ptrFloat(decision.Action.Price.Amount)
		event.PriceCurrency = ptrString(decision.Action.Price.Currency)
		event.PriceUnit = ptrString(decision.Action.Price.Unit)
	}

	if decision.Action.Type == config.ActionBlock && decision.Action.Status != 0 {
		event.Status = decision.Action.Status
	}

	return event
}

func (e Event) ReceiptPayload() receipt.Payload {
	eventID := e.EventID
	if eventID == "" && e.ID != 0 {
		eventID = fmt.Sprintf("legacy-%d", e.ID)
	}

	payload := receipt.Payload{
		Version: "crawlwall.receipt/v1",
		EventID: eventID,
		SiteID:  e.SiteID,
		Time:    e.TS.Format(time.RFC3339),
		Bot: receipt.BotPayload{
			ID:       e.BotID,
			Class:    e.BotClass,
			Verified: e.BotVerified,
		},
		Request: receipt.RequestPayload{
			Host:   e.Host,
			Method: e.Method,
			Path:   e.Path,
		},
		Policy: receipt.PolicyPayload{
			RuleID: e.RuleID,
			Action: e.Action,
		},
	}

	if e.PriceAmount != nil && e.PriceCurrency != nil && e.PriceUnit != nil {
		payload.Metering = &receipt.MeteringPayload{
			Amount:   *e.PriceAmount,
			Currency: *e.PriceCurrency,
			Unit:     *e.PriceUnit,
		}
	}

	return payload
}

type noopLedger struct{}

func Open(dsn string, enabled bool) (Ledger, error) {
	if !enabled {
		return noopLedger{}, nil
	}
	return openSQLite(dsn)
}

func (noopLedger) WriteEvent(context.Context, Event) error { return nil }
func (noopLedger) Report(context.Context, time.Time) ([]ReportRow, error) {
	return nil, nil
}
func (noopLedger) ExportJSONL(context.Context, io.Writer) error { return nil }
func (noopLedger) Close() error                                 { return nil }
func (noopLedger) Prune(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func ParseExportLine(line []byte) (*ExportRecord, error) {
	var exportRecord ExportRecord
	if err := json.Unmarshal(line, &exportRecord); err == nil && exportRecord.Event.SiteID != "" {
		return &exportRecord, nil
	}

	var envelope receipt.Envelope
	if err := json.Unmarshal(line, &envelope); err != nil {
		return nil, fmt.Errorf("decode export line: %w", err)
	}
	return &ExportRecord{Receipt: &envelope}, nil
}

func ptrFloat(value float64) *float64 { return &value }
func ptrString(value string) *string  { return &value }

func newEventID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err == nil {
		return "evt_" + hex.EncodeToString(buf)
	}
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}
