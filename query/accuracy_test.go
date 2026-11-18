package query_test

import (
	"net/netip"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
)

func TestH1_InterleavedEqualCostRoutes(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal, permit("1", "", "", "", "", ""))
	cfg.Routes = append(cfg.Routes,
		firemon.Route{VirtualRouter: "vr", Destination: prefix("192.0.2.0/24"), NextHop: netip.MustParseAddr("203.0.113.1")},
		firemon.Route{VirtualRouter: "vr", Destination: prefix("198.51.100.0/24"), NextHop: netip.MustParseAddr("203.0.113.1")},
		firemon.Route{VirtualRouter: "vr", Destination: prefix("192.0.2.0/24"), NextHop: netip.MustParseAddr("172.16.0.254")},
	)
	res := queryOne(t, cfg, req(t, "10.0.0.9", "192.0.2.10", "tcp/22"))
	if len(res.Paths) != 2 {
		t.Fatalf("both equal-cost routes declared apart must carry traffic, got %d paths", len(res.Paths))
	}
}

func TestH1_RecursiveNextHopIndependentOfOrder(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal, permit("1", "", "", "", "", ""))
	cfg.Routes = append(cfg.Routes,
		firemon.Route{VirtualRouter: "vr", Destination: prefix("192.0.2.0/24"), NextHop: netip.MustParseAddr("198.18.0.1")},
		firemon.Route{VirtualRouter: "vr", Destination: prefix("198.18.0.0/24"), NextHop: netip.MustParseAddr("172.16.0.254")},
	)
	res := queryOne(t, cfg, req(t, "10.0.0.9", "192.0.2.10", "tcp/22"))
	if len(res.Paths) != 1 || res.Paths[0].To != "dmz" {
		t.Fatalf("the next hop resolves through the more specific route to dmz: %+v", res.Paths)
	}
}

func TestH2_OneBudgetPerQuery(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal, permit("1", "", "", "", "", ""))
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := req(t, "10.0.0.9", "8.8.8.8", "tcp/443")
	r.DstDomains = []string{"a.example", "b.example", "c.example"}
	r.Applications = []string{"ssl", "web-browsing"}
	res, err := query.New(fw, query.Options{MaxPaths: 2}).Query(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Paths) > 2 || !res.Incomplete || res.Verdict != query.VerdictIndeterminate {
		t.Fatalf("budget of 2 paths across targets: %d paths, incomplete %v, %s", len(res.Paths), res.Incomplete, res.Verdict)
	}
}

func TestH7_UnresolvedDomainFromIPv6Source(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal, permit("1", "", "", "", "", ""))
	cfg.Interfaces[0].Addresses = append(cfg.Interfaces[0].Addresses, prefix("2001:db8::2/64"))
	cfg.Interfaces[1].Addresses = append(cfg.Interfaces[1].Addresses, prefix("2001:db8:1::1/64"))
	cfg.Routes = append(cfg.Routes, firemon.Route{VirtualRouter: "vr", Destination: prefix("::/0"), NextHop: netip.MustParseAddr("2001:db8::1")})
	r := req(t, "2001:db8:1::9", "8.8.8.8", "tcp/443")
	r.Dst = r.Dst.Subtract(r.Dst)
	r.DstDomains = []string{"www.example.com"}
	res := queryOne(t, cfg, r)
	if len(res.Paths) != 1 || res.Paths[0].To != "untrust" {
		t.Fatalf("an IPv6 client reaches the name by the IPv6 default route: %+v", res.Paths)
	}
}
