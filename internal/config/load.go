package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decode config file: %w", err)
	}

	cfg.applyDefaults()
	cfg.normalize(filepath.Dir(path))

	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if strings.TrimSpace(c.Version) == "" {
		c.Version = VersionV1
	}
	if strings.TrimSpace(c.Site.Mode) == "" {
		c.Site.Mode = SiteModeEnforce
	}
	if strings.TrimSpace(c.Runtime.FailMode) == "" {
		c.Runtime.FailMode = FailModeBlock
	}
	if c.Runtime.DefaultAction.Type == "" {
		c.Runtime.DefaultAction.Type = ActionAllow
	}
}

func (c *Config) normalize(baseDir string) {
	if c.Sets == nil {
		c.Sets = map[string]any{}
	} else {
		c.Sets = normalizeValue(c.Sets).(map[string]any)
	}

	if c.Receipts.Enabled && c.Receipts.Signer.KeyFile != "" && !filepath.IsAbs(c.Receipts.Signer.KeyFile) {
		c.Receipts.Signer.KeyFile = filepath.Clean(filepath.Join(baseDir, c.Receipts.Signer.KeyFile))
	}
}

func normalizeValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = normalizeValue(item)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[fmt.Sprint(key)] = normalizeValue(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, normalizeValue(item))
		}
		return out
	default:
		return typed
	}
}
