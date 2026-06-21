package crawlwall

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/jolovicdev/crawlwall/internal/bot"
	"github.com/jolovicdev/crawlwall/internal/config"
	"github.com/jolovicdev/crawlwall/internal/ledger"
	"github.com/jolovicdev/crawlwall/internal/policy"
	"github.com/jolovicdev/crawlwall/internal/ratelimit"
	"github.com/jolovicdev/crawlwall/internal/receipt"
	"github.com/jolovicdev/crawlwall/internal/verify"
)

type testNextHandler func(http.ResponseWriter, *http.Request) error

func (h testNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return h(w, r)
}

func TestServeHTTPBlocksUnknownProtectedPathAndSignsReceipt(t *testing.T) {
	mod, publicKey := newTestModule(t, `{"prefixes":[{"ipv4Prefix":"20.125.66.80/28"}]}`)
	defer closeLedger(t, mod)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://localhost/archive/a", nil)
	request.RemoteAddr = "198.51.100.10:1234"

	calledNext := false
	err := mod.ServeHTTP(recorder, request, testNextHandler(func(w http.ResponseWriter, r *http.Request) error {
		calledNext = true
		w.WriteHeader(http.StatusOK)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if calledNext {
		t.Fatalf("next handler should not be called for blocked request")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("recorder.Code = %d", recorder.Code)
	}

	records := exportedRecords(t, mod)
	if len(records) != 1 {
		t.Fatalf("len(records) = %d", len(records))
	}
	if records[0].Event.Action != "block" {
		t.Fatalf("action = %q", records[0].Event.Action)
	}
	if records[0].Receipt == nil {
		t.Fatalf("expected receipt for blocked protected-path request")
	}
	if err := receipt.VerifyEnvelope(publicKey, *records[0].Receipt); err != nil {
		t.Fatalf("VerifyEnvelope() error = %v", err)
	}
}

func TestServeHTTPMetersVerifiedTrainingBotAndSignsReceipt(t *testing.T) {
	mod, publicKey := newTestModule(t, `{"prefixes":[{"ipv4Prefix":"20.125.66.80/28"}]}`)
	defer closeLedger(t, mod)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://localhost/archive/a", nil)
	request.Header.Set("User-Agent", "GPTBot/1.1")
	request.RemoteAddr = "20.125.66.81:1234"

	err := mod.ServeHTTP(recorder, request, testNextHandler(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("recorder.Code = %d", recorder.Code)
	}

	records := exportedRecords(t, mod)
	if len(records) != 1 {
		t.Fatalf("len(records) = %d", len(records))
	}
	record := records[0]
	if record.Event.Action != "allow_metered" {
		t.Fatalf("action = %q", record.Event.Action)
	}
	if record.Event.PriceAmount == nil || *record.Event.PriceAmount != 0.002 {
		t.Fatalf("price_amount = %v", record.Event.PriceAmount)
	}
	if record.Receipt == nil {
		t.Fatalf("expected receipt for metered request")
	}
	if err := receipt.VerifyEnvelope(publicKey, *record.Receipt); err != nil {
		t.Fatalf("VerifyEnvelope() error = %v", err)
	}

	tampered := *record.Receipt
	tampered.ReceiptID = "tampered-" + tampered.ReceiptID
	if err := receipt.VerifyEnvelope(publicKey, tampered); err == nil {
		t.Fatalf("VerifyEnvelope() error = nil for tampered receipt ID")
	}
}

func TestServeHTTPBlocksPolicyEvaluationError(t *testing.T) {
	mod, _ := newTestModuleWithPolicy(t, `{"prefixes":[{"ipv4Prefix":"20.125.66.80/28"}]}`, func(keyPath, rangesURL string) string {
		return strings.TrimSpace(`
version: crawlwall.io/v1

site:
  id: test-site
  host: localhost
  mode: enforce

runtime:
  fail_mode: block
  default_action:
    type: allow

ledger:
  enabled: true

receipts:
  enabled: false

bots:
  - id: unknown
    name: Unknown
    class: unknown
    match:
      default: true
    verify:
      type: none

sets:
  protected_paths: "/archive"

rules:
  - id: bad_dynamic_set_shape
    priority: 10
    when: >
      sets.protected_paths.exists(p, request.path.startsWith(p))
    action:
      type: block
      status: 403
      reason: unknown_crawler_protected_path
`) + "\n"
	})
	defer closeLedger(t, mod)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://localhost/archive/a", nil)
	request.RemoteAddr = "198.51.100.10:1234"

	calledNext := false
	err := mod.ServeHTTP(recorder, request, testNextHandler(func(w http.ResponseWriter, r *http.Request) error {
		calledNext = true
		w.WriteHeader(http.StatusOK)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if calledNext {
		t.Fatalf("next handler should not be called for policy evaluation failure")
	}
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("recorder.Code = %d", recorder.Code)
	}

	records := exportedRecords(t, mod)
	if len(records) != 1 {
		t.Fatalf("len(records) = %d", len(records))
	}
	if records[0].Event.RuleID != "runtime.policy_error" {
		t.Fatalf("rule_id = %q", records[0].Event.RuleID)
	}
	if records[0].Event.Action != "block" {
		t.Fatalf("action = %q", records[0].Event.Action)
	}
	if records[0].Event.ActionReason != "policy_evaluation_failed" {
		t.Fatalf("action_reason = %q", records[0].Event.ActionReason)
	}
}

func TestServeHTTPShadowModeLogsBlockWithoutEnforcing(t *testing.T) {
	mod, _ := newTestModuleWithPolicy(t, `{"prefixes":[{"ipv4Prefix":"20.125.66.80/28"}]}`, func(keyPath, rangesURL string) string {
		return strings.TrimSpace(`
version: crawlwall.io/v1

site:
  id: test-site
  host: localhost
  mode: shadow

runtime:
  fail_mode: block
  default_action:
    type: allow

ledger:
  enabled: true

receipts:
  enabled: false

bots:
  - id: unknown
    name: Unknown
    class: unknown
    match:
      default: true
    verify:
      type: none

sets:
  protected_paths:
    - "/archive"

rules:
  - id: block_unknown_protected_paths
    priority: 10
    when: >
      bot.class == "unknown" &&
      sets.protected_paths.exists(p, request.path.startsWith(p))
    action:
      type: block
      status: 403
      reason: unknown_crawler_protected_path
`) + "\n"
	})
	defer closeLedger(t, mod)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://localhost/archive/a", nil)
	request.RemoteAddr = "198.51.100.10:1234"

	calledNext := false
	err := mod.ServeHTTP(recorder, request, testNextHandler(func(w http.ResponseWriter, r *http.Request) error {
		calledNext = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !calledNext {
		t.Fatalf("next handler should be called in shadow mode")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("recorder.Code = %d", recorder.Code)
	}

	records := exportedRecords(t, mod)
	if len(records) != 1 {
		t.Fatalf("len(records) = %d", len(records))
	}
	if records[0].Event.RuleID != "block_unknown_protected_paths" {
		t.Fatalf("rule_id = %q", records[0].Event.RuleID)
	}
	if records[0].Event.Action != "block" {
		t.Fatalf("action = %q", records[0].Event.Action)
	}
	if records[0].Event.Status != http.StatusOK {
		t.Fatalf("logged status = %d", records[0].Event.Status)
	}
}

func verifierErrorPolicy(mode string) func(keyPath, rangesURL string) string {
	return func(keyPath, rangesURL string) string {
		return strings.TrimSpace(`
version: crawlwall.io/v1

site:
  id: test-site
  host: localhost
  mode: ` + mode + `

runtime:
  fail_mode: block
  default_action:
    type: allow

ledger:
  enabled: true

receipts:
  enabled: false

bots:
  - id: gptbot
    name: GPTBot
    class: ai_training
    match:
      user_agents:
        - "GPTBot"
    verify:
      type: ip_ranges
      sources:
        - "` + rangesURL + `"
      refresh: 1h
      stale_action: fail_closed
      max_stale: 0s

  - id: unknown
    name: Unknown
    class: unknown
    match:
      default: true
    verify:
      type: none

rules:
  - id: block_spoofed_known_bots
    priority: 10
    when: >
      bot.claimed && !bot.verified
    action:
      type: block
      status: 403
      reason: spoofed_bot
`) + "\n"
	}
}

func TestServeHTTPShadowModeDoesNotBlockOnVerifierError(t *testing.T) {
	// The ranges source returns a document with no CIDRs, so the ip_ranges
	// verifier fails closed and Verify returns an error.
	mod, _ := newTestModuleWithPolicy(t, `{}`, verifierErrorPolicy("shadow"))
	defer closeLedger(t, mod)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://localhost/archive/a", nil)
	request.Header.Set("User-Agent", "GPTBot/1.1")
	request.RemoteAddr = "198.51.100.10:1234"

	calledNext := false
	err := mod.ServeHTTP(recorder, request, testNextHandler(func(w http.ResponseWriter, r *http.Request) error {
		calledNext = true
		w.WriteHeader(http.StatusOK)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !calledNext {
		t.Fatalf("next handler should be called: shadow mode must not block on verifier errors")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("recorder.Code = %d, want 200", recorder.Code)
	}

	records := exportedRecords(t, mod)
	if len(records) != 1 {
		t.Fatalf("len(records) = %d", len(records))
	}
	if records[0].Event.Action != "block" || records[0].Event.RuleID != "block_spoofed_known_bots" {
		t.Fatalf("logged decision = %q via %q, want would-be block from policy", records[0].Event.Action, records[0].Event.RuleID)
	}
	if records[0].Event.Status != http.StatusOK {
		t.Fatalf("logged status = %d, want upstream 200", records[0].Event.Status)
	}
}

func TestServeHTTPEnforceModeBlocksOnVerifierError(t *testing.T) {
	mod, _ := newTestModuleWithPolicy(t, `{}`, verifierErrorPolicy("enforce"))
	defer closeLedger(t, mod)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://localhost/archive/a", nil)
	request.Header.Set("User-Agent", "GPTBot/1.1")
	request.RemoteAddr = "198.51.100.10:1234"

	calledNext := false
	err := mod.ServeHTTP(recorder, request, testNextHandler(func(w http.ResponseWriter, r *http.Request) error {
		calledNext = true
		w.WriteHeader(http.StatusOK)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if calledNext {
		t.Fatalf("next handler should not be called when enforcing fail_mode block")
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("recorder.Code = %d, want 503", recorder.Code)
	}

	records := exportedRecords(t, mod)
	if len(records) != 1 {
		t.Fatalf("len(records) = %d", len(records))
	}
	if records[0].Event.RuleID != "runtime.verifier_error" || records[0].Event.ActionReason != "verification_failed" {
		t.Fatalf("logged decision = %q/%q, want runtime.verifier_error/verification_failed", records[0].Event.RuleID, records[0].Event.ActionReason)
	}
}

func TestServeHTTPUsesTrustedClientIPVariableForVerification(t *testing.T) {
	mod, _ := newTestModule(t, `{"prefixes":[{"ipv4Prefix":"20.125.66.80/28"}]}`)
	defer closeLedger(t, mod)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://localhost/archive/a", nil)
	request.Header.Set("User-Agent", "GPTBot/1.1")
	request.RemoteAddr = "198.51.100.10:1234"
	request = request.WithContext(context.WithValue(request.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "20.125.66.81",
	}))

	calledNext := false
	err := mod.ServeHTTP(recorder, request, testNextHandler(func(w http.ResponseWriter, r *http.Request) error {
		calledNext = true
		w.WriteHeader(http.StatusOK)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !calledNext {
		t.Fatalf("next handler should be called for verified client IP")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("recorder.Code = %d", recorder.Code)
	}

	records := exportedRecords(t, mod)
	if len(records) != 1 {
		t.Fatalf("len(records) = %d", len(records))
	}
	if !records[0].Event.BotVerified {
		t.Fatalf("BotVerified = false")
	}
	if records[0].Event.RemoteIP != "20.125.66.81" {
		t.Fatalf("RemoteIP = %q", records[0].Event.RemoteIP)
	}
}

func TestServeHTTPPreservesResponseFlush(t *testing.T) {
	mod, _ := newTestModule(t, `{"prefixes":[{"ipv4Prefix":"20.125.66.80/28"}]}`)
	defer closeLedger(t, mod)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://localhost/public/a", nil)
	request.RemoteAddr = "198.51.100.10:1234"

	err := mod.ServeHTTP(recorder, request, testNextHandler(func(w http.ResponseWriter, r *http.Request) error {
		_, _ = w.Write([]byte("stream"))
		if err := http.NewResponseController(w).Flush(); err != nil {
			return err
		}
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("recorder.Code = %d", recorder.Code)
	}
	if recorder.Body.String() != "stream" {
		t.Fatalf("body = %q", recorder.Body.String())
	}
}

func TestServeHTTPRateLimitsVerifiedTrainingBot(t *testing.T) {
	mod, _ := newTestModule(t, `{"prefixes":[{"ipv4Prefix":"20.125.66.80/28"}]}`)
	defer closeLedger(t, mod)

	for i := 0; i < 120; i++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "http://localhost/public/a", nil)
		request.Header.Set("User-Agent", "GPTBot/1.1")
		request.RemoteAddr = "20.125.66.81:1234"

		err := mod.ServeHTTP(recorder, request, testNextHandler(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusOK)
			return nil
		}))
		if err != nil {
			t.Fatalf("ServeHTTP() iteration %d error = %v", i, err)
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("recorder.Code iteration %d = %d", i, recorder.Code)
		}
	}

	lastRecorder := httptest.NewRecorder()
	lastRequest := httptest.NewRequest(http.MethodGet, "http://localhost/public/a", nil)
	lastRequest.Header.Set("User-Agent", "GPTBot/1.1")
	lastRequest.RemoteAddr = "20.125.66.81:1234"

	err := mod.ServeHTTP(lastRecorder, lastRequest, testNextHandler(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() last error = %v", err)
	}
	if lastRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("lastRecorder.Code = %d", lastRecorder.Code)
	}

	records := exportedRecords(t, mod)
	if len(records) != 121 {
		t.Fatalf("len(records) = %d", len(records))
	}
	if records[len(records)-1].Event.Action != "rate_limit_exceeded" {
		t.Fatalf("last action = %q", records[len(records)-1].Event.Action)
	}
}

func newTestModule(t *testing.T, ipRangesResponse string) (*Crawlwall, ed25519.PublicKey) {
	t.Helper()
	return newTestModuleWithPolicy(t, ipRangesResponse, func(keyPath, rangesURL string) string {
		return strings.TrimSpace(`
version: crawlwall.io/v1

site:
  id: test-site
  host: localhost
  mode: enforce

runtime:
  fail_mode: allow
  default_action:
    type: allow

ledger:
  enabled: true

receipts:
  enabled: true
  signer:
    type: ed25519
    key_file: `+keyPath+`

bots:
  - id: gptbot
    name: GPTBot
    class: ai_training
    match:
      user_agents:
        - "GPTBot"
    verify:
      type: ip_ranges
      sources:
        - "`+rangesURL+`"
      refresh: 1h

  - id: unknown
    name: Unknown
    class: unknown
    match:
      default: true
    verify:
      type: none

sets:
  protected_paths:
    - "/archive"
    - "/datasets"
    - "/reports"

rules:
  - id: block_spoofed_known_bots
    priority: 10
    when: >
      bot.claimed && !bot.verified
    action:
      type: block
      status: 403
      reason: spoofed_bot
    audit:
      receipt: true

  - id: meter_training_on_protected_paths
    priority: 200
    when: >
      bot.verified &&
      bot.class == "ai_training" &&
      sets.protected_paths.exists(p, request.path.startsWith(p))
    action:
      type: allow_metered
      price:
        amount: 0.002
        currency: USD
        unit: request
    audit:
      receipt: true

  - id: rate_limit_ai_training_elsewhere
    priority: 300
    when: >
      bot.verified && bot.class == "ai_training"
    action:
      type: rate_limit
      limit:
        key: "bot.id"
        rpm: 120
    audit:
      receipt: true

  - id: block_unknown_protected_paths
    priority: 900
    when: >
      bot.class == "unknown" &&
      sets.protected_paths.exists(p, request.path.startsWith(p))
    action:
      type: block
      status: 403
      reason: unknown_crawler_protected_path
    audit:
      receipt: true
`) + "\n"
	})
}

func newTestModuleWithPolicy(t *testing.T, ipRangesResponse string, buildPolicy func(keyPath, rangesURL string) string) (*Crawlwall, ed25519.PublicKey) {
	t.Helper()

	rangesServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(ipRangesResponse))
	}))
	t.Cleanup(rangesServer.Close)

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "crawlwall.db")
	policyPath := filepath.Join(tempDir, "crawlwall.yaml")
	keyPath := filepath.Join(tempDir, "crawlwall.key")
	publicPath := filepath.Join(tempDir, "crawlwall.pub")
	if err := receipt.GenerateKeyPairFiles(keyPath, publicPath); err != nil {
		t.Fatalf("GenerateKeyPairFiles() error = %v", err)
	}

	policyYAML := buildPolicy(keyPath, rangesServer.URL)

	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}

	cfg, err := config.LoadFile(policyPath)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	led, err := ledger.Open("sqlite://"+dbPath, true)
	if err != nil {
		t.Fatalf("ledger.Open() error = %v", err)
	}

	engine, err := policy.NewEngine(cfg)
	if err != nil {
		t.Fatalf("policy.NewEngine() error = %v", err)
	}

	signer, err := receipt.NewSigner(cfg.Receipts)
	if err != nil {
		t.Fatalf("receipt.NewSigner() error = %v", err)
	}
	publicKey, err := receipt.LoadPublicKeyFile(publicPath)
	if err != nil {
		t.Fatalf("LoadPublicKeyFile() error = %v", err)
	}

	return &Crawlwall{
		logger:   zap.NewNop(),
		config:   cfg,
		bots:     bot.NewIdentifier(cfg.Bots),
		verifier: verify.NewService(cfg.Bots, zap.NewNop()),
		policy:   engine,
		ledger:   led,
		limiter:  ratelimit.New(),
		signer:   signer,
	}, publicKey
}

func exportedRecords(t *testing.T, mod *Crawlwall) []ledger.ExportRecord {
	t.Helper()

	var buf bytes.Buffer
	if err := mod.ledger.ExportJSONL(context.Background(), &buf); err != nil {
		t.Fatalf("ExportJSONL() error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var out []ledger.ExportRecord
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		record, err := ledger.ParseExportLine([]byte(line))
		if err != nil {
			t.Fatalf("ParseExportLine() error = %v", err)
		}
		out = append(out, *record)
	}
	return out
}

func closeLedger(t *testing.T, mod *Crawlwall) {
	t.Helper()
	if mod != nil && mod.ledger != nil {
		if err := mod.ledger.Close(); err != nil {
			t.Fatalf("ledger.Close() error = %v", err)
		}
	}
}
