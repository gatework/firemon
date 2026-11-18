package dns_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/gatework/firemon/adapter/dns"
)

func TestResolver_Resolve(t *testing.T) {
	t.Parallel()
	r := dns.Resolver{Lookup: func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host == "a.example.com" {
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		}
		return nil, errors.New("no such host")
	}, MaxNames: 2}
	got := r.Resolve(t.Context(), []string{"*.example.com", "a.example.com", "missing.test", "late.test"})
	if len(got) != 1 || got["a.example.com"][0].String() != "192.0.2.1" {
		t.Fatalf("got %v", got)
	}
}
