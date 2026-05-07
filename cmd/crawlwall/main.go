package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"

	"github.com/jolovicdev/crawlwall/internal/bot"
	"github.com/jolovicdev/crawlwall/internal/config"
	"github.com/jolovicdev/crawlwall/internal/ledger"
	"github.com/jolovicdev/crawlwall/internal/policy"
	"github.com/jolovicdev/crawlwall/internal/receipt"
	"github.com/jolovicdev/crawlwall/internal/scaffold"
	"github.com/jolovicdev/crawlwall/internal/verify"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	ctx := context.Background()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	switch args[0] {
	case "init":
		return runInit(args[1:])
	case "policy":
		return runPolicy(ctx, args[1:])
	case "ledger":
		return runLedger(ctx, args[1:])
	case "receipts":
		return runReceipts(ctx, args[1:])
	case "verifiers":
		return runVerifiers(ctx, args[1:])
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("dir", ".", "target directory")
	profile := fs.String("profile", "minimal", "starter profile: minimal or full")
	force := fs.Bool("force", false, "overwrite existing files")
	writeCaddyfile := fs.Bool("write-caddyfile", true, "write a starter Caddyfile")
	writeGitignore := fs.Bool("write-gitignore", true, "write a starter .gitignore")
	generateKeys := fs.Bool("generate-keys", true, "generate ed25519 receipt keys")
	if err := fs.Parse(args); err != nil {
		return err
	}

	policyText, err := scaffold.Policy(*profile)
	if err != nil {
		return err
	}

	targetDir := filepath.Clean(*dir)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}

	written := []string{}
	if err := writeScaffoldFile(filepath.Join(targetDir, "crawlwall.yaml"), policyText, *force, 0o644); err != nil {
		return err
	}
	written = append(written, "crawlwall.yaml")

	if *writeCaddyfile {
		if err := writeScaffoldFile(filepath.Join(targetDir, "Caddyfile"), scaffold.Caddyfile, *force, 0o644); err != nil {
			return err
		}
		written = append(written, "Caddyfile")
	}

	if *writeGitignore {
		if err := writeScaffoldFile(filepath.Join(targetDir, ".gitignore"), scaffold.Gitignore, *force, 0o644); err != nil {
			return err
		}
		written = append(written, ".gitignore")
	}

	if *generateKeys {
		privatePath := filepath.Join(targetDir, "crawlwall.key")
		publicPath := filepath.Join(targetDir, "crawlwall.pub")
		if err := writeKeyPair(privatePath, publicPath, *force); err != nil {
			return err
		}
		written = append(written, "crawlwall.key", "crawlwall.pub")
	}

	fmt.Printf("initialized crawlwall scaffold in %s\n", targetDir)
	for _, name := range written {
		fmt.Printf("  wrote %s\n", name)
	}
	if !*generateKeys {
		fmt.Println("receipt keys were not generated; full configs that enable receipts will need them later")
	}
	return nil
}

func runPolicy(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("policy command is required")
	}

	switch args[0] {
	case "check":
		fs := flag.NewFlagSet("policy check", flag.ContinueOnError)
		configPath := fs.String("config", "./crawlwall.yaml", "path to crawlwall yaml")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		cfg, err := config.LoadFile(*configPath)
		if err != nil {
			return err
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
		if _, err := policy.NewEngine(cfg); err != nil {
			return err
		}

		fmt.Printf("policy ok: %d rules, %d bots\n", len(cfg.Rules), len(cfg.Bots))
		return nil

	case "eval":
		fs := flag.NewFlagSet("policy eval", flag.ContinueOnError)
		configPath := fs.String("config", "./crawlwall.yaml", "path to crawlwall yaml")
		userAgent := fs.String("ua", "", "request user agent")
		path := fs.String("path", "/", "request path")
		host := fs.String("host", "localhost", "request host")
		method := fs.String("method", "GET", "request method")
		ipAddress := fs.String("ip", "127.0.0.1", "remote IP")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		cfg, err := config.LoadFile(*configPath)
		if err != nil {
			return err
		}
		if err := cfg.Validate(); err != nil {
			return err
		}

		output, err := evaluatePolicy(ctx, cfg, policyEvalRequest{
			UserAgent: *userAgent,
			Path:      *path,
			Host:      *host,
			Method:    *method,
			IP:        *ipAddress,
		})
		if err != nil {
			return err
		}

		return writeJSON(os.Stdout, output)
	case "test":
		fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
		configPath := fs.String("config", "./crawlwall.yaml", "path to crawlwall yaml")
		fixturesPath := fs.String("fixtures", "./examples/policy-fixtures.yaml", "path to policy fixture yaml")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		cfg, err := config.LoadFile(*configPath)
		if err != nil {
			return err
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
		if _, err := policy.NewEngine(cfg); err != nil {
			return err
		}

		fixtures, err := loadPolicyFixtures(*fixturesPath)
		if err != nil {
			return err
		}
		return runPolicyFixtureTests(ctx, cfg, fixtures)
	default:
		return fmt.Errorf("unknown policy command %q", args[0])
	}
}

type policyEvalRequest struct {
	UserAgent string
	Path      string
	Host      string
	Method    string
	IP        string
}

type policyEvalResult struct {
	Bot          map[string]any  `json:"bot"`
	Request      map[string]any  `json:"request"`
	Verification verify.Result   `json:"verification"`
	Decision     policy.Decision `json:"decision"`
	Status       int             `json:"status"`
	Summary      string          `json:"summary"`
}

func evaluatePolicy(ctx context.Context, cfg *config.Config, req policyEvalRequest) (*policyEvalResult, error) {
	engine, err := policy.NewEngine(cfg)
	if err != nil {
		return nil, err
	}

	identifier := bot.NewIdentifier(cfg.Bots)
	identified := identifier.Identify(req.UserAgent)
	verifier := verify.NewService(cfg.Bots, zap.NewNop())
	parsedIP := netParse(req.IP)
	verification, verifyErr := verifier.Verify(ctx, verify.Input{
		Bot:      identified,
		RemoteIP: parsedIP,
	})
	if verifyErr != nil {
		verification.Reason = strings.TrimPrefix(verification.Reason+": "+verifyErr.Error(), ": ")
	}

	input := policy.Input{
		Bot: policy.BotInput{
			ID:       identified.ID,
			Name:     identified.Name,
			Class:    identified.Class,
			Claimed:  identified.Claimed,
			Verified: verification.Verified,
			Operator: identified.Operator,
		},
		Request: policy.RequestInput{
			Host:      defaultString(req.Host, "localhost"),
			Method:    defaultString(req.Method, http.MethodGet),
			Path:      defaultString(req.Path, "/"),
			IP:        parsedIP.String(),
			UserAgent: req.UserAgent,
			Headers:   map[string]string{},
		},
		Site:     engine.SiteInput(),
		Sets:     engine.SetsInput(),
		Counters: map[string]any{},
		License:  map[string]any{},
	}

	decision, err := engine.Evaluate(input)
	if err != nil {
		return nil, err
	}
	if decision.Action.Type == config.ActionRateLimit && decision.Action.Limit != nil {
		decision.Action.Limit.ResolvedKey = policy.ResolvePath(input.Vars(), decision.Action.Limit.Key)
	}

	return &policyEvalResult{
		Bot:          input.Bot.Map(),
		Request:      input.Request.Map(),
		Verification: verification,
		Decision:     decision,
		Status:       predictedStatus(decision.Action),
		Summary:      policy.DescribeDecision(decision),
	}, nil
}

func predictedStatus(action config.Action) int {
	switch action.Type {
	case config.ActionBlock:
		if action.Status != 0 {
			return action.Status
		}
		return http.StatusForbidden
	case config.ActionRateLimit:
		return http.StatusTooManyRequests
	default:
		return http.StatusOK
	}
}

type policyFixtureFile struct {
	Fixtures []policyFixture `yaml:"fixtures"`
}

type policyFixture struct {
	Name    string                `yaml:"name"`
	Request policyFixtureRequest  `yaml:"request"`
	Expect  policyFixtureExpected `yaml:"expect"`
}

type policyFixtureRequest struct {
	UserAgent string `yaml:"user_agent"`
	Path      string `yaml:"path"`
	Host      string `yaml:"host"`
	Method    string `yaml:"method"`
	IP        string `yaml:"ip"`
}

type policyFixtureExpected struct {
	BotID    string `yaml:"bot_id"`
	BotClass string `yaml:"bot_class"`
	Verified *bool  `yaml:"verified"`
	RuleID   string `yaml:"rule_id"`
	Action   string `yaml:"action"`
	Reason   string `yaml:"reason"`
	Status   *int   `yaml:"status"`
}

func loadPolicyFixtures(path string) ([]policyFixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy fixtures: %w", err)
	}

	var file policyFixtureFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode policy fixtures: %w", err)
	}
	if len(file.Fixtures) == 0 {
		return nil, fmt.Errorf("policy fixtures must contain at least one fixture")
	}
	return file.Fixtures, nil
}

func runPolicyFixtureTests(ctx context.Context, cfg *config.Config, fixtures []policyFixture) error {
	failures := 0
	for i, fixture := range fixtures {
		name := fixture.Name
		if strings.TrimSpace(name) == "" {
			name = fmt.Sprintf("fixture_%d", i+1)
		}

		result, err := evaluatePolicy(ctx, cfg, policyEvalRequest{
			UserAgent: fixture.Request.UserAgent,
			Path:      fixture.Request.Path,
			Host:      fixture.Request.Host,
			Method:    fixture.Request.Method,
			IP:        fixture.Request.IP,
		})
		if err != nil {
			failures++
			fmt.Printf("not ok %s: %v\n", name, err)
			continue
		}

		mismatches := fixtureMismatches(fixture.Expect, result)
		if len(mismatches) > 0 {
			failures++
			fmt.Printf("not ok %s\n", name)
			for _, mismatch := range mismatches {
				fmt.Printf("  %s\n", mismatch)
			}
			continue
		}

		fmt.Printf("ok %s\n", name)
	}

	if failures > 0 {
		return fmt.Errorf("policy fixtures failed: %d failed, %d passed", failures, len(fixtures)-failures)
	}

	fmt.Printf("policy fixtures ok: %d passed\n", len(fixtures))
	return nil
}

func fixtureMismatches(expected policyFixtureExpected, result *policyEvalResult) []string {
	var mismatches []string
	if expected.BotID != "" {
		mismatches = appendMismatch(mismatches, "bot_id", expected.BotID, fmt.Sprint(result.Bot["id"]))
	}
	if expected.BotClass != "" {
		mismatches = appendMismatch(mismatches, "bot_class", expected.BotClass, fmt.Sprint(result.Bot["class"]))
	}
	if expected.Verified != nil && *expected.Verified != result.Verification.Verified {
		mismatches = append(mismatches, fmt.Sprintf("verified: expected %t, got %t", *expected.Verified, result.Verification.Verified))
	}
	if expected.RuleID != "" {
		mismatches = appendMismatch(mismatches, "rule_id", expected.RuleID, result.Decision.RuleID)
	}
	if expected.Action != "" {
		mismatches = appendMismatch(mismatches, "action", expected.Action, string(result.Decision.Action.Type))
	}
	if expected.Reason != "" {
		mismatches = appendMismatch(mismatches, "reason", expected.Reason, result.Decision.Action.Reason)
	}
	if expected.Status != nil && *expected.Status != result.Status {
		mismatches = append(mismatches, fmt.Sprintf("status: expected %d, got %d", *expected.Status, result.Status))
	}
	return mismatches
}

func appendMismatch(mismatches []string, field, expected, actual string) []string {
	if expected != actual {
		return append(mismatches, fmt.Sprintf("%s: expected %q, got %q", field, expected, actual))
	}
	return mismatches
}

func runLedger(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("ledger command is required")
	}

	switch args[0] {
	case "report":
		fs := flag.NewFlagSet("ledger report", flag.ContinueOnError)
		dbPath := fs.String("db", "./crawlwall.db", "sqlite database path")
		since := fs.String("since", "24h", "time window")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		duration, err := time.ParseDuration(*since)
		if err != nil {
			return err
		}

		led, err := ledger.Open("sqlite://"+strings.TrimPrefix(*dbPath, "sqlite://"), true)
		if err != nil {
			return err
		}
		defer led.Close()

		report, err := led.Report(ctx, time.Now().Add(-duration))
		if err != nil {
			return err
		}
		printReport(os.Stdout, report)
		return nil

	case "export":
		fs := flag.NewFlagSet("ledger export", flag.ContinueOnError)
		dbPath := fs.String("db", "./crawlwall.db", "sqlite database path")
		format := fs.String("format", "jsonl", "export format")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *format != "jsonl" {
			return fmt.Errorf("unsupported export format %q", *format)
		}

		led, err := ledger.Open("sqlite://"+strings.TrimPrefix(*dbPath, "sqlite://"), true)
		if err != nil {
			return err
		}
		defer led.Close()

		return led.ExportJSONL(ctx, os.Stdout)
	default:
		return fmt.Errorf("unknown ledger command %q", args[0])
	}
}

func runVerifiers(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("verifiers command is required")
	}

	switch args[0] {
	case "status":
		fs := flag.NewFlagSet("verifiers status", flag.ContinueOnError)
		configPath := fs.String("config", "./crawlwall.yaml", "path to crawlwall yaml")
		format := fs.String("format", "table", "output format: table or json")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		cfg, err := config.LoadFile(*configPath)
		if err != nil {
			return err
		}
		if err := cfg.Validate(); err != nil {
			return err
		}

		service := verify.NewService(cfg.Bots, zap.NewNop())
		statuses := service.CacheStatus(ctx, cfg.Bots)
		switch *format {
		case "json":
			return writeJSON(os.Stdout, statuses)
		case "table":
			printVerifierStatuses(os.Stdout, statuses)
			return nil
		default:
			return fmt.Errorf("unsupported verifiers status format %q", *format)
		}
	default:
		return fmt.Errorf("unknown verifiers command %q", args[0])
	}
}

func printVerifierStatuses(w io.Writer, statuses []verify.CacheStatus) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "Bot\tType\tState\tCIDRs\tLast fetch\tExpires\tStale action\tStale until\tError")
	for _, status := range statuses {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			status.BotID,
			status.Type,
			status.State,
			status.CIDRCount,
			formatOptionalTime(status.LastFetch),
			formatOptionalTime(status.ExpiresAt),
			defaultString(status.StaleAction, "-"),
			formatOptionalTime(status.StaleUntil),
			status.Error,
		)
	}
	_ = tw.Flush()
}

func runReceipts(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("receipts command is required")
	}

	switch args[0] {
	case "verify":
		fs := flag.NewFlagSet("receipts verify", flag.ContinueOnError)
		filePath := fs.String("file", "", "path to receipt export")
		publicKeyPath := fs.String("public-key", "", "path to PEM public key")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *filePath == "" || *publicKeyPath == "" {
			return fmt.Errorf("--file and --public-key are required")
		}

		publicKey, err := receipt.LoadPublicKeyFile(*publicKeyPath)
		if err != nil {
			return err
		}

		file, err := os.Open(*filePath)
		if err != nil {
			return err
		}
		defer file.Close()

		total, verified, skipped, err := verifyReceipts(ctx, file, publicKey)
		if err != nil {
			return err
		}
		fmt.Printf("verified %d/%d receipt lines", verified, total)
		if skipped > 0 {
			fmt.Printf(" (%d non-receipt lines skipped)", skipped)
		}
		fmt.Println()
		return nil
	default:
		return fmt.Errorf("unknown receipts command %q", args[0])
	}
}

func verifyReceipts(_ context.Context, r io.Reader, publicKey ed25519.PublicKey) (int, int, int, error) {
	scanner := bufio.NewScanner(r)
	total := 0
	verified := 0
	skipped := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		record, err := ledger.ParseExportLine([]byte(line))
		if err != nil {
			return total, verified, skipped, err
		}

		var envelope *receipt.Envelope
		switch {
		case record.Receipt != nil:
			envelope = record.Receipt
		case record.Event.ReceiptSignature != "":
			envelope = &receipt.Envelope{
				ReceiptID: record.Event.ReceiptID,
				Payload:   record.Event.ReceiptPayload(),
				Signature: record.Event.ReceiptSignature,
			}
		default:
			skipped++
			continue
		}

		total++
		if err := receipt.VerifyEnvelope(publicKey, *envelope); err != nil {
			return total, verified, skipped, fmt.Errorf("receipt line %d: %w", total, err)
		}
		verified++
	}

	return total, verified, skipped, scanner.Err()
}

func printReport(w io.Writer, report []ledger.ReportRow) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "Bot\tClass\tVerified\tRequests\tAllowed\tBlocked\tMetered")
	for _, row := range report {
		verified := "no"
		if row.Verified {
			verified = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\n", row.BotName, row.Class, verified, row.Requests, row.Allowed, row.Blocked, row.Metered)
	}
	_ = tw.Flush()
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func netParse(value string) net.IP {
	if ip := net.ParseIP(value); ip != nil {
		return ip
	}
	return net.IPv4zero
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}

func usage() {
	fmt.Println(`crawlwall commands:
  crawlwall init --profile minimal --dir .
  crawlwall policy check --config ./crawlwall.yaml
  crawlwall policy eval --config ./crawlwall.yaml --ua "GPTBot/1.1" --path "/archive/a"
  crawlwall policy test --config ./crawlwall.yaml --fixtures ./examples/policy-fixtures.yaml
  crawlwall verifiers status --config ./crawlwall.yaml
  crawlwall ledger report --db ./crawlwall.db --since 24h
  crawlwall ledger export --db ./crawlwall.db --format jsonl
  crawlwall receipts verify --file receipts.jsonl --public-key crawlwall.pub`)
}

func writeScaffoldFile(path, contents string, force bool, perm os.FileMode) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing file %s; rerun with --force", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create parent directory for %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(contents), perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeKeyPair(privatePath, publicPath string, force bool) error {
	if !force {
		for _, path := range []string{privatePath, publicPath} {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("refusing to overwrite existing file %s; rerun with --force", path)
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}
	return receipt.GenerateKeyPairFiles(privatePath, publicPath)
}
