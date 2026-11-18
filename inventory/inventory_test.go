package inventory_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

var now = time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)

type link struct {
	iface, zone, addr string
}

type route struct{ dst, hop string }

// firewall builds a layer-3 firewall with one zone per interface.
func firewall(t *testing.T, links []link, routes []route, rules ...firemon.SecurityRule) *firemon.Firewall {
	t.Helper()
	fw, err := newFirewall(links, routes, rules...)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func newFirewall(links []link, routes []route, rules ...firemon.SecurityRule) (*firemon.Firewall, error) {
	cfg := &firemon.Config{
		Vendor:         firemon.VendorPaloAlto,
		Semantics:      firemon.Semantics{InterzoneAction: firemon.ActionDeny, IntrazoneAction: firemon.ActionPermit, DefaultVirtualRouter: "vr"},
		VirtualRouters: []firemon.VirtualRouter{{Name: "vr"}},
		Rules:          rules,
	}
	for _, l := range links {
		cfg.Zones = append(cfg.Zones, firemon.Zone{Name: l.zone})
		cfg.Interfaces = append(cfg.Interfaces, firemon.Interface{Name: l.iface, Zone: l.zone, VirtualRouter: "vr", Addresses: []netip.Prefix{netip.MustParsePrefix(l.addr)}})
	}
	for _, r := range routes {
		cfg.Routes = append(cfg.Routes, firemon.Route{VirtualRouter: "vr", Destination: netip.MustParsePrefix(r.dst), NextHop: netip.MustParseAddr(r.hop)})
	}
	return firemon.Compile(cfg)
}

func lab(t *testing.T, coreRules ...firemon.SecurityRule) *inventory.Inventory {
	t.Helper()
	core := firewall(t,
		[]link{{"c0", "transit", "10.0.0.2/30"}, {"c1", "users", "10.1.0.1/16"}, {"c2", "servers", "10.2.0.1/16"}},
		[]route{{"0.0.0.0/0", "10.0.0.1"}}, coreRules...)
	edge := firewall(t,
		[]link{{"e0", "internet", "203.0.113.2/30"}, {"e1", "inside", "10.0.0.1/30"}},
		[]route{{"0.0.0.0/0", "203.0.113.1"}, {"10.0.0.0/8", "10.0.0.2"}},
		firemon.SecurityRule{ID: "out", From: []string{"inside"}, To: []string{"internet"}, Action: firemon.ActionPermit})
	dc := firewall(t,
		[]link{{"d0", "up", "192.168.9.2/30"}, {"d1", "racks", "192.168.10.1/24"}},
		[]route{{"0.0.0.0/0", "192.168.9.1"}})
	inv, err := inventory.New([]inventory.Member{{"core", core}, {"edge", edge}, {"dc", dc}}, inventory.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func request(src, dst, svc string) query.Request {
	s, _ := traffic.ParseAddressSet(src)
	d, _ := traffic.ParseAddressSet(dst)
	v, _ := traffic.ParseServiceSet(svc)
	return query.Request{Src: s, Dst: d, Service: v}
}

func names(t inventory.Trace) []string {
	var out []string
	for _, c := range t.Crossings {
		out = append(out, c.Firewall+"("+c.Paths[0].From+">"+c.Paths[0].To+")")
	}
	return out
}

func TestInventory_Locate(t *testing.T) {
	t.Parallel()
	webOut := firemon.SecurityRule{ID: "web", From: []string{"users"}, To: []string{"transit"}, Action: firemon.ActionPermit}
	tests := []struct {
		name     string
		inv      *inventory.Inventory
		req      query.Request
		crossing []string
		verdict  query.Verdict
	}{
		{"internet access crosses core and edge", lab(t, webOut), request("10.1.0.5", "8.8.8.8", "tcp/443"),
			[]string{"core(users>transit)", "edge(inside>internet)"}, query.VerdictAllowed},
		{"internal flow crosses only core", lab(t, webOut), request("10.1.0.5", "10.2.0.9", "tcp/22"),
			[]string{"core(users>servers)"}, query.VerdictDenied},
		{"denied on one firewall denies the trace", lab(t), request("10.1.0.5", "8.8.8.8", "tcp/443"),
			[]string{"core(users>transit)", "edge(inside>internet)"}, query.VerdictPartial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tr, err := tt.inv.Locate(tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if got := names(tr); !slices.Equal(got, tt.crossing) || tr.Verdict != tt.verdict {
				t.Fatalf("got %v %s, want %v %s", got, tr.Verdict, tt.crossing, tt.verdict)
			}
		})
	}
}

func TestInventory_Plan(t *testing.T) {
	t.Parallel()
	in := design.Intent{Name: "req"}
	in.Src, _ = traffic.ParseAddressSet("10.1.0.5")
	in.Dst, _ = traffic.ParseAddressSet("8.8.8.8")
	in.Service, _ = traffic.ParseServiceSet("tcp/443")
	plans, err := lab(t).Plan(in)
	if err != nil {
		t.Fatal(err)
	}
	if plans["core"].Status != design.StatusChange || !plans["core"].Verified || plans["edge"].Status != design.StatusNoChange {
		t.Fatalf("core %s edge %s", plans["core"].Status, plans["edge"].Status)
	}
	if _, ok := plans["dc"]; ok {
		t.Fatal("dc is not on the path")
	}
}

func TestNew_RejectsDuplicates(t *testing.T) {
	t.Parallel()
	fw := firewall(t, []link{{"x0", "a", "10.9.0.1/24"}}, nil)
	if _, err := inventory.New([]inventory.Member{{"a", fw}, {"a", fw}}, inventory.Options{}); err == nil {
		t.Fatal("want duplicate error")
	}
}
