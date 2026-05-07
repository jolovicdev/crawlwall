package verify

import (
	"context"
	"net"
	"strings"
)

type reverseDNSVerifier struct {
	allowedSuffixes []string
	resolver        *net.Resolver
}

func newReverseDNSVerifier(allowedSuffixes []string) Verifier {
	return reverseDNSVerifier{
		allowedSuffixes: allowedSuffixes,
		resolver:        net.DefaultResolver,
	}
}

func (v reverseDNSVerifier) Verify(ctx context.Context, ip net.IP) (Result, error) {
	names, err := v.resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return Result{Type: "reverse_dns", Reason: "ptr_lookup_failed"}, err
	}

	for _, name := range names {
		host := strings.TrimSuffix(strings.ToLower(name), ".")
		if !v.allowed(host) {
			continue
		}

		addrs, err := v.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return Result{Type: "reverse_dns", Reason: "forward_lookup_failed"}, err
		}
		for _, addr := range addrs {
			if addr.IP.Equal(ip) {
				return Result{
					Verified: true,
					Type:     "reverse_dns",
					Reason:   "reverse_dns_match",
				}, nil
			}
		}
	}

	return Result{
		Verified: false,
		Type:     "reverse_dns",
		Reason:   "reverse_dns_no_roundtrip_match",
	}, nil
}

func (v reverseDNSVerifier) allowed(host string) bool {
	for _, suffix := range v.allowedSuffixes {
		normalized := strings.TrimPrefix(strings.ToLower(suffix), ".")
		if host == normalized || strings.HasSuffix(host, "."+normalized) {
			return true
		}
	}
	return false
}
