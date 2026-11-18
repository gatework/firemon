package query_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// Regression tests for the second review round. Each test name carries the
// finding number of the plan (Q1-Q13).

func queryOne(t *testing.T, cfg *firemon.Config, req query.Request) *query.Result {
	t.Helper()
	res, err := engine(t, cfg).Query(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func req(t *testing.T, src, dst, service string) query.Request {
	t.Helper()
	return query.Request{Src: addrs(t, src), Dst: addrs(t, dst), Service: svc(t, service)}
}

func TestQ1_UnreachableNextHopFallsThrough(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal, permit("1", "trust", "untrust", "", "", "https"))
	cfg.Routes = append(cfg.Routes, firemon.Route{VirtualRouter: "vr", Destination: prefix("8.8.0.0/16"), NextHop: netip.MustParseAddr("192.0.2.99")})
	res := queryOne(t, cfg, req(t, "10.0.0.9", "8.8.8.8", "tcp/443"))
	if res.Verdict != query.VerdictAllowed || !res.Unrouted.IsEmpty() || res.Paths[0].To != "untrust" {
		t.Fatalf("got %s unrouted %s", res.Verdict, res.Unrouted)
	}
}

func TestQ2_AddressFamiliesStaySeparate(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal, permit("1", "", "", "", "", "https"))
	res := queryOne(t, cfg, req(t, "any", "172.16.0.10", "tcp/443"))
	for _, p := range res.Paths {
		if p.Original.Src.Overlaps(traffic.AnyIPv6()) {
			t.Fatalf("IPv6 source reached an IPv4 destination: %s", p.Original)
		}
	}
	if res.Verdict == query.VerdictIndeterminate {
		t.Fatal("IPv4-only routing must not make an IPv4 request indeterminate")
	}
}

func dnatTo(zone string) firemon.DynamicNAT {
	return firemon.DynamicNAT{
		ID: "d1", To: []string{zone},
		TranslatedDestination: firemon.Translation{Mode: firemon.TranslationModeAddress, Addresses: []firemon.AddressRef{inline("172.16.0.10/32")}},
	}
}

func TestQ3_DestinationNATChecksTheZoneOfTheRequestPart(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageTranslated, permit("1", "", "", "", "", ""))
	cfg.DynamicNATs = []firemon.DynamicNAT{dnatTo("untrust")}
	res := queryOne(t, cfg, req(t, "203.0.113.9", "10.0.0.50", "tcp/80"))
	for _, p := range res.Paths {
		if p.DestinationNAT != nil {
			t.Fatalf("traffic routed to trust was translated by a rule for untrust: %+v", p)
		}
	}
	res = queryOne(t, cfg, req(t, "10.0.0.9", "8.8.8.8", "tcp/80"))
	if res.Paths[0].DestinationNAT == nil || res.Paths[0].To != "dmz" {
		t.Fatalf("traffic to untrust must be translated to the dmz server: %+v", res.Paths)
	}
}

func TestQ4_UndecidableNATMakesThePathUnknown(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageTranslated, permit("1", "", "", "", "", ""))
	n := dnatTo("untrust")
	n.To = nil
	n.Destination = []firemon.AddressRef{firemon.NamedAddress("cdn")} // FQDN: undecidable
	cfg.DynamicNATs = []firemon.DynamicNAT{n}
	res := queryOne(t, cfg, req(t, "10.0.0.9", "8.8.8.8", "tcp/80"))
	if res.Verdict != query.VerdictIndeterminate || len(res.Paths[0].NATUncertain) == 0 {
		t.Fatalf("got %s %v", res.Verdict, res.Paths[0].NATUncertain)
	}
}

func TestQ4_ExemptionConsumesTheTraffic(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageTranslated, permit("1", "", "", "", "", ""))
	exempt := firemon.DynamicNAT{ID: "x", Destination: []firemon.AddressRef{inline("8.8.8.8/32")},
		TranslatedDestination: firemon.Translation{Mode: firemon.TranslationModeNone}}
	cfg.DynamicNATs = []firemon.DynamicNAT{exempt, dnatTo("untrust")}
	res := queryOne(t, cfg, req(t, "10.0.0.9", "8.8.8.8", "tcp/80"))
	if res.Paths[0].DestinationNAT != nil {
		t.Fatal("an earlier no-NAT rule must exempt the traffic")
	}
}

func TestQ5_SingleOrderNATIsFirstMatchAcrossSides(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal, permit("1", "", "", "", "", ""))
	cfg.Semantics.NATOrder = firemon.NATOrderSingle
	snatOnly := firemon.DynamicNAT{ID: "s1", Precedence: 1, From: []string{"trust"},
		TranslatedSource: firemon.Translation{Mode: firemon.TranslationModeInterface, Interface: "e0"}}
	dnat := dnatTo("untrust")
	dnat.Precedence = 2
	cfg.DynamicNATs = []firemon.DynamicNAT{snatOnly, dnat}
	res := queryOne(t, cfg, req(t, "10.0.0.9", "8.8.8.8", "tcp/80"))
	p := res.Paths[0]
	if p.DestinationNAT != nil || len(p.SourceNAT) != 1 || p.SourceNAT[0].Rule.Spec().ID != "s1" {
		t.Fatalf("the first matching rule decides both sides: dnat %v snat %v", p.DestinationNAT, p.SourceNAT)
	}
}

func TestQ6Q7_StaticNATNarrowsAndChecksZones(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageTranslated, permit("1", "", "", "", "", ""))
	cfg.StaticNATs = []firemon.StaticNAT{{
		ID: "b1", Real: firemon.InlineAddress(firemon.PrefixEntry(prefix("10.0.0.0/31"))),
		Mapped: firemon.InlineAddress(firemon.PrefixEntry(prefix("198.51.100.0/31"))), Zones: []string{"untrust"},
	}}
	res := queryOne(t, cfg, query.Request{Src: addrs(t, "192.0.2.1"), Dst: addrs(t, "198.51.100.1"), Service: svc(t, "tcp/22"), FromZone: "untrust"})
	p := res.Paths[0]
	if p.DestinationNAT == nil || p.Original.Dst.String() != "198.51.100.1" || p.Policy.Dst.String() != "10.0.0.1" {
		t.Fatalf("inbound static NAT: %+v", p)
	}
	res = queryOne(t, cfg, query.Request{Src: addrs(t, "172.16.0.5"), Dst: addrs(t, "198.51.100.1"), Service: svc(t, "tcp/22"), FromZone: "dmz"})
	if res.Paths[0].DestinationNAT != nil {
		t.Fatal("the mapping is visible only from untrust")
	}
}

func TestQ9_EgressUsesTheIngressRoutingContext(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal, permit("1", "", "", "", "", ""))
	cfg.VirtualRouters = append(cfg.VirtualRouters, firemon.VirtualRouter{Name: "vr2"})
	cfg.Zones = append(cfg.Zones, firemon.Zone{Name: "lab"}, firemon.Zone{Name: "lab-out"})
	cfg.Interfaces = append(cfg.Interfaces,
		firemon.Interface{Name: "e9", Zone: "lab", VirtualRouter: "vr2", Addresses: []netip.Prefix{prefix("192.168.9.1/24")}},
		firemon.Interface{Name: "e8", Zone: "lab-out", VirtualRouter: "vr2", Addresses: []netip.Prefix{prefix("192.168.8.1/24")}})
	cfg.Routes = append(cfg.Routes, firemon.Route{VirtualRouter: "vr", Destination: prefix("192.168.9.0/24"), NextVirtualRouter: "vr2"})
	res := queryOne(t, cfg, req(t, "192.168.9.5", "192.168.8.5", "tcp/22"))
	if len(res.Paths) != 1 || res.Paths[0].From != "lab" || res.Paths[0].To != "lab-out" {
		t.Fatalf("paths %+v unrouted %s", res.Paths, res.Unrouted)
	}
}

func TestQ10_PathBudgetMarksIncomplete(t *testing.T) {
	t.Parallel()
	fw, err := firemon.Compile(lab(firemon.AddressStageOriginal, permit("1", "", "", "", "", "")))
	if err != nil {
		t.Fatal(err)
	}
	e := query.New(fw, query.Options{Now: func() time.Time { return at }, MaxPaths: 1})
	res, err := e.Query(req(t, "10.0.0.9", "172.16.0.10,8.8.8.8", "tcp/22"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete || res.Verdict != query.VerdictIndeterminate {
		t.Fatalf("got incomplete=%v %s", res.Incomplete, res.Verdict)
	}
}

func TestQ11_RecurrenceBoundaries(t *testing.T) {
	t.Parallel()
	day := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	allDay := firemon.Recurrence{Start: 8 * time.Hour, End: 8 * time.Hour}
	if !allDay.Contains(day.Add(3*time.Hour)) || !allDay.Contains(day.Add(20*time.Hour)) {
		t.Error("Start == End covers the whole day")
	}
}

func TestQ12_EqualCostRoutesAllCarryTraffic(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal, permit("1", "", "", "", "", ""))
	cfg.Routes = append(cfg.Routes, firemon.Route{VirtualRouter: "vr", Destination: prefix("0.0.0.0/0"), NextHop: netip.MustParseAddr("172.16.0.254")})
	res := queryOne(t, cfg, req(t, "10.0.0.9", "8.8.8.8", "tcp/22"))
	if len(res.Paths) != 2 {
		t.Fatalf("want one path per equal-cost route, got %d", len(res.Paths))
	}
}

func TestQ13_MappedIPv4(t *testing.T) {
	t.Parallel()
	s := traffic.NewAddressSet(netip.MustParsePrefix("::ffff:10.0.0.0/104"))
	if !s.Contains(netip.MustParseAddr("10.1.1.1")) || !s.Contains(netip.MustParseAddr("::ffff:10.1.1.1")) {
		t.Fatalf("mapped prefix %s", s)
	}
}
