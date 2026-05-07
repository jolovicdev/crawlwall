package bot

import "github.com/jolovicdev/crawlwall/internal/config"

type Identified struct {
	ID         string
	Name       string
	Class      string
	Operator   string
	Claimed    bool
	VerifyType string
	Verify     config.VerifyConfig
}

type Registered struct {
	ID       string
	Name     string
	Class    string
	Operator string
	Match    config.MatchConfig
	Verify   config.VerifyConfig
}
