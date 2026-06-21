package crawlwall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/jolovicdev/crawlwall/internal/bot"
	"github.com/jolovicdev/crawlwall/internal/config"
	"github.com/jolovicdev/crawlwall/internal/ledger"
	"github.com/jolovicdev/crawlwall/internal/policy"
	"github.com/jolovicdev/crawlwall/internal/ratelimit"
	"github.com/jolovicdev/crawlwall/internal/receipt"
	"github.com/jolovicdev/crawlwall/internal/verify"
)

func init() {
	caddy.RegisterModule(Crawlwall{})
}

type Crawlwall struct {
	PolicyFile string `json:"policy_file,omitempty"`
	LedgerDSN  string `json:"ledger_dsn,omitempty"`
	FailMode   string `json:"fail_mode,omitempty"`

	logger   *zap.Logger
	config   *config.Config
	bots     *bot.Identifier
	verifier *verify.Service
	policy   *policy.Engine
	ledger   ledger.Ledger
	limiter  *ratelimit.Limiter
	signer   *receipt.Signer
}

func (Crawlwall) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.crawlwall",
		New: func() caddy.Module { return new(Crawlwall) },
	}
}

func (m *Crawlwall) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	if strings.TrimSpace(m.PolicyFile) == "" {
		return errors.New("crawlwall policy file is required")
	}

	cfg, err := config.LoadFile(m.PolicyFile)
	if err != nil {
		return fmt.Errorf("load crawlwall policy: %w", err)
	}

	if strings.TrimSpace(m.FailMode) != "" {
		cfg.Runtime.FailMode = m.FailMode
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	led, err := ledger.Open(m.LedgerDSN, cfg.Ledger.Enabled)
	if err != nil {
		return fmt.Errorf("open ledger: %w", err)
	}

	engine, err := policy.NewEngine(cfg)
	if err != nil {
		_ = led.Close()
		return fmt.Errorf("compile policy: %w", err)
	}

	signer, err := receipt.NewSigner(cfg.Receipts)
	if err != nil {
		_ = led.Close()
		return fmt.Errorf("load receipt signer: %w", err)
	}

	m.config = cfg
	m.bots = bot.NewIdentifier(cfg.Bots)
	m.verifier = verify.NewService(cfg.Bots, m.logger)
	m.policy = engine
	m.ledger = led
	m.limiter = ratelimit.New()
	m.signer = signer

	// Warm the ip_ranges caches and start background refreshers so the request
	// path serves from a warm cache instead of fetching sources inline.
	m.verifier.Start(ctx)

	m.logger.Info("crawlwall provisioned",
		zap.String("policy_file", m.PolicyFile),
		zap.String("ledger_dsn", m.LedgerDSN),
		zap.String("site_id", cfg.Site.ID),
		zap.Int("rules", len(cfg.Rules)),
		zap.Int("bots", len(cfg.Bots)),
	)

	return nil
}

func (m *Crawlwall) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	start := time.Now()
	remoteIP := remoteIPFromRequest(r)
	identifiedBot := m.bots.Identify(r.UserAgent())

	verification, verifyErr := m.verifier.Verify(r.Context(), verify.Input{
		Bot:      identifiedBot,
		RemoteIP: remoteIP,
		Headers:  r.Header,
	})

	// observe and shadow are non-enforcing modes; only enforce may affect
	// real traffic, including the verifier fail-closed path below.
	enforce := m.config.Site.Mode == config.SiteModeEnforce

	if verifyErr != nil {
		m.logger.Warn("crawlwall verifier error",
			zap.String("bot_id", identifiedBot.ID),
			zap.String("remote_ip", remoteIP.String()),
			zap.Error(verifyErr),
		)

		if enforce && m.config.Runtime.FailMode == config.FailModeBlock {
			event := ledger.EventFromRequest(start, r, remoteIP, identifiedBot, verification, m.policy.DefaultDecision(), m.config.Site.ID)
			event.Action = string(config.ActionBlock)
			event.ActionReason = "verification_failed"
			event.RuleID = "runtime.verifier_error"
			event.Status = http.StatusServiceUnavailable
			event.DurationMS = time.Since(start).Milliseconds()
			m.writeLedgerAndReceipt(r.Context(), &event)
			http.Error(w, "crawlwall verifier unavailable", http.StatusServiceUnavailable)
			return nil
		}
	}

	input := policy.Input{
		Bot: policy.BotInput{
			ID:       identifiedBot.ID,
			Name:     identifiedBot.Name,
			Class:    identifiedBot.Class,
			Claimed:  identifiedBot.Claimed,
			Verified: verification.Verified,
			Operator: identifiedBot.Operator,
		},
		Request: policy.RequestInput{
			Host:      r.Host,
			Method:    r.Method,
			Path:      r.URL.Path,
			Query:     r.URL.RawQuery,
			IP:        remoteIP.String(),
			UserAgent: r.UserAgent(),
			Headers:   headersToMap(r.Header),
		},
		Site:   m.policy.SiteInput(),
		Sets:   m.policy.SetsInput(),
		Labels: m.policy.LabelsInput(identifiedBot, r),
	}

	decision, evalErr := m.policy.Evaluate(input)
	if evalErr != nil {
		m.logger.Warn("crawlwall policy evaluation error",
			zap.String("bot_id", identifiedBot.ID),
			zap.String("remote_ip", remoteIP.String()),
			zap.Error(evalErr),
		)
		decision = m.policy.EvaluationErrorDecision(m.config.Runtime.FailMode)
	}
	if decision.Action.Type == config.ActionRateLimit && decision.Action.Limit != nil {
		decision.Action.Limit.ResolvedKey = policy.ResolvePath(input.Vars(), decision.Action.Limit.Key)
	}

	event := ledger.EventFromRequest(start, r, remoteIP, identifiedBot, verification, decision, m.config.Site.ID)
	event.DurationMS = time.Since(start).Milliseconds()

	switch decision.Action.Type {
	case config.ActionBlock:
		if enforce {
			status := decision.Action.Status
			if status == 0 {
				status = http.StatusForbidden
			}
			event.Status = status
			event.DurationMS = time.Since(start).Milliseconds()
			m.writeLedgerAndReceipt(r.Context(), &event)
			http.Error(w, decision.Action.Reason, status)
			return nil
		}
	case config.ActionRateLimit:
		if enforce && decision.Action.Limit != nil && !m.limiter.Allow(decision.Action.Limit.ResolvedKey, decision.Action.Limit.RPM) {
			event.Status = http.StatusTooManyRequests
			event.Action = "rate_limit_exceeded"
			event.ActionReason = "rate_limit_exceeded"
			event.DurationMS = time.Since(start).Milliseconds()
			m.writeLedgerAndReceipt(r.Context(), &event)
			http.Error(w, "rate limited by crawlwall", http.StatusTooManyRequests)
			return nil
		}
	}

	cw := caddyhttp.NewResponseRecorder(w, nil, nil)
	err := next.ServeHTTP(cw, r)

	status := cw.Status()
	if status == 0 {
		status = http.StatusOK
	}
	event.Status = status
	event.BytesSent = int64(cw.Size())
	event.DurationMS = time.Since(start).Milliseconds()

	m.writeLedgerAndReceipt(r.Context(), &event)

	return err
}

func (m *Crawlwall) Cleanup() error {
	if m.verifier != nil {
		m.verifier.Stop()
	}
	if m.ledger != nil {
		return m.ledger.Close()
	}
	return nil
}

func (m *Crawlwall) writeLedgerAndReceipt(ctx context.Context, event *ledger.Event) {
	if m.ledger == nil {
		return
	}

	if m.signer.Enabled() && (event.Action == string(config.ActionAllowMetered) || event.ReceiptRequested) {
		envelope, err := m.signer.Sign(event.ReceiptPayload())
		if err != nil {
			m.logger.Warn("crawlwall receipt signing failed", zap.Error(err))
		} else {
			event.ReceiptID = envelope.ReceiptID
			event.ReceiptSignature = envelope.Signature
		}
	}

	if err := m.ledger.WriteEvent(ctx, *event); err != nil {
		m.logger.Warn("crawlwall ledger write failed", zap.Error(err))
	}
}

func remoteIPFromRequest(r *http.Request) net.IP {
	if clientIP, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok {
		if ip := parseIP(clientIP); ip != nil {
			return ip
		}
	}

	if ip := parseIP(r.RemoteAddr); ip != nil {
		return ip
	}

	return net.IPv4zero
}

func parseIP(value string) net.IP {
	host := strings.TrimSpace(value)
	if host == "" {
		return nil
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}

	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil
	}

	return ip
}

func headersToMap(headers http.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		out[strings.ToLower(key)] = strings.Join(values, ", ")
	}
	return out
}

var (
	_ caddy.Provisioner           = (*Crawlwall)(nil)
	_ caddy.CleanerUpper          = (*Crawlwall)(nil)
	_ caddyhttp.MiddlewareHandler = (*Crawlwall)(nil)
)
