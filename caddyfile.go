package crawlwall

import (
	"fmt"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("crawlwall", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Crawlwall

	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "policy":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				m.PolicyFile = h.Val()
			case "ledger":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				m.LedgerDSN = h.Val()
			case "fail_mode":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				m.FailMode = h.Val()
			default:
				return nil, fmt.Errorf("unrecognized crawlwall option %q", h.Val())
			}
		}
	}

	return &m, nil
}
