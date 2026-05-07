package config

type Config struct {
	Version  string         `yaml:"version"`
	Site     SiteConfig     `yaml:"site"`
	Runtime  RuntimeConfig  `yaml:"runtime"`
	Ledger   LedgerConfig   `yaml:"ledger"`
	Receipts ReceiptsConfig `yaml:"receipts"`
	Bots     []BotConfig    `yaml:"bots"`
	Sets     map[string]any `yaml:"sets"`
	Rules    []RuleConfig   `yaml:"rules"`
}

type SiteConfig struct {
	ID   string `yaml:"id"`
	Host string `yaml:"host"`
	Mode string `yaml:"mode"`
}

type RuntimeConfig struct {
	FailMode      string `yaml:"fail_mode"`
	DefaultAction Action `yaml:"default_action"`
}

type LedgerConfig struct {
	Enabled       bool `yaml:"enabled"`
	SampleHumans  bool `yaml:"sample_humans"`
	WriteBodyHash bool `yaml:"write_body_hash"`
}

type ReceiptsConfig struct {
	Enabled bool         `yaml:"enabled"`
	Signer  SignerConfig `yaml:"signer"`
}

type SignerConfig struct {
	Type    string `yaml:"type"`
	KeyFile string `yaml:"key_file"`
}

type BotConfig struct {
	ID       string       `yaml:"id"`
	Name     string       `yaml:"name"`
	Class    string       `yaml:"class"`
	Operator string       `yaml:"operator,omitempty"`
	Match    MatchConfig  `yaml:"match"`
	Verify   VerifyConfig `yaml:"verify"`
}

type MatchConfig struct {
	UserAgents []string `yaml:"user_agents"`
	Default    bool     `yaml:"default"`
}

type VerifyConfig struct {
	Type            string   `yaml:"type"`
	AllowedSuffixes []string `yaml:"allowed_suffixes"`
	Sources         []string `yaml:"sources"`
	Refresh         string   `yaml:"refresh"`
	StaleAction     string   `yaml:"stale_action"`
	MaxStale        string   `yaml:"max_stale"`
}

type RuleConfig struct {
	ID       string `yaml:"id"`
	Priority int    `yaml:"priority"`
	When     string `yaml:"when"`
	Action   Action `yaml:"action"`
	Audit    Audit  `yaml:"audit"`
}

type Audit struct {
	Receipt bool     `yaml:"receipt"`
	Tags    []string `yaml:"tags"`
}

type ActionType string

const (
	ActionAllow        ActionType = "allow"
	ActionBlock        ActionType = "block"
	ActionRateLimit    ActionType = "rate_limit"
	ActionAllowMetered ActionType = "allow_metered"
)

const (
	VersionV1             = "crawlwall.io/v1"
	SiteModeObserve       = "observe"
	SiteModeEnforce       = "enforce"
	SiteModeShadow        = "shadow"
	FailModeAllow         = "allow"
	FailModeBlock         = "block"
	StaleActionFailClosed = "fail_closed"
	StaleActionUseStale   = "use_stale"
)

type Action struct {
	Type   ActionType `yaml:"type"`
	Status int        `yaml:"status,omitempty"`
	Reason string     `yaml:"reason,omitempty"`

	Limit *Limit `yaml:"limit,omitempty"`
	Price *Price `yaml:"price,omitempty"`
}

type Limit struct {
	Key         string `yaml:"key"`
	RPM         int    `yaml:"rpm"`
	ResolvedKey string `yaml:"-"`
}

type Price struct {
	Amount   float64 `yaml:"amount"`
	Currency string  `yaml:"currency"`
	Unit     string  `yaml:"unit"`
}
