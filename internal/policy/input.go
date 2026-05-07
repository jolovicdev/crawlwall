package policy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/jolovicdev/crawlwall/internal/bot"
)

type Input struct {
	Bot     BotInput
	Request RequestInput
	Site    map[string]any
	Sets    map[string]any
	Labels  map[string]any
}

func (i Input) Vars() map[string]any {
	return map[string]any{
		"bot":     i.Bot.Map(),
		"request": i.Request.Map(),
		"site":    i.Site,
		"sets":    i.Sets,
		"labels":  i.Labels,
	}
}

type BotInput struct {
	ID       string
	Name     string
	Class    string
	Claimed  bool
	Verified bool
	Signed   bool
	Operator string
}

func (b BotInput) Map() map[string]any {
	return map[string]any{
		"id":       b.ID,
		"name":     b.Name,
		"class":    b.Class,
		"claimed":  b.Claimed,
		"verified": b.Verified,
		"signed":   b.Signed,
		"operator": b.Operator,
	}
}

type RequestInput struct {
	Host      string
	Method    string
	Path      string
	Query     string
	IP        string
	UserAgent string
	Headers   map[string]string
}

func (r RequestInput) Map() map[string]any {
	headers := make(map[string]any, len(r.Headers))
	for key, value := range r.Headers {
		headers[key] = value
	}

	return map[string]any{
		"host":       r.Host,
		"method":     r.Method,
		"path":       r.Path,
		"query":      r.Query,
		"ip":         r.IP,
		"user_agent": r.UserAgent,
		"headers":    headers,
	}
}

func ResolvePath(vars map[string]any, path string) string {
	current := any(vars)
	for _, segment := range strings.Split(path, ".") {
		nextMap, ok := current.(map[string]any)
		if !ok {
			return path
		}
		next, exists := nextMap[segment]
		if !exists {
			return path
		}
		current = next
	}
	return fmt.Sprint(current)
}

func DefaultLabelsInput(identified bot.Identified, r *http.Request) map[string]any {
	return map[string]any{
		"bot_id": identified.ID,
		"host":   r.Host,
		"path":   r.URL.Path,
	}
}
