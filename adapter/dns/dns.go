// Package dns resolves destination domain names for domain-based policy
// queries with the system resolver, bounded in time and number of names.
// Wildcard patterns are not resolvable and are left out.
package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Resolver looks names up. The zero value uses net.DefaultResolver, a
// five-second timeout per name and at most 32 names.
type Resolver struct {
	Lookup   func(ctx context.Context, network, host string) ([]netip.Addr, error)
	Timeout  time.Duration
	MaxNames int
}

// Resolve returns the addresses of each resolvable name. Names that fail
// to resolve are missing from the result; queries then treat them as
// unresolved.
func (r Resolver) Resolve(ctx context.Context, names []string) map[string][]netip.Addr {
	lookup := r.Lookup
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	limit := r.MaxNames
	if limit <= 0 {
		limit = 32
	}
	out := map[string][]netip.Addr{}
	for i, name := range names {
		if i >= limit || ctx.Err() != nil {
			break
		}
		if strings.Contains(name, "*") {
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, timeout)
		addrs, err := lookup(lctx, "ip", name)
		cancel()
		if err == nil && len(addrs) > 0 {
			out[name] = addrs
		}
	}
	return out
}
