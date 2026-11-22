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
	inv, err := inventory.New([]inventory.Member{{Name: "core", Firewall: core}, {Name: "edge", Firewall: edge}, {Name: "dc", Firewall: dc}}, inventory.Options{Now: func() time.Time { return now }})
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
		{"internet access crosses core and edge", lab(t, webOut), request("10.1.0.5", "203.0.113.208", "tcp/443"),
			[]string{"core(users>transit)", "edge(inside>internet)"}, query.VerdictAllowed},
		{"internal flow crosses only core", lab(t, webOut), request("10.1.0.5", "10.2.0.9", "tcp/22"),
			[]string{"core(users>servers)"}, query.VerdictDenied},
		{"denied on one firewall denies the trace", lab(t), request("10.1.0.5", "203.0.113.208", "tcp/443"),
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
	in.Dst, _ = traffic.ParseAddressSet("203.0.113.208")
	in.Service, _ = traffic.ParseServiceSet("tcp/443")
	cps, err := lab(t).Plan(in)
	if err != nil {
		t.Fatal(err)
	}
	plans := map[string]*design.Plan{}
	for _, cp := range cps {
		plans[cp.Cluster] = cp.Plan
	}
	if plans["core"] == nil || plans["core"].Status != design.StatusChange || !plans["core"].Verified || plans["edge"].Status != design.StatusNoChange {
		t.Fatalf("plans %+v", plans)
	}
	if _, ok := plans["dc"]; ok {
		t.Fatal("dc is not on the path")
	}
}

func TestNew_RejectsDuplicates(t *testing.T) {
	t.Parallel()
	fw := firewall(t, []link{{"x0", "a", "10.9.0.1/24"}}, nil)
	if _, err := inventory.New([]inventory.Member{{Name: "a", Firewall: fw}, {Name: "a", Firewall: fw}}, inventory.Options{}); err == nil {
		t.Fatal("want duplicate error")
	}
}

func TestInventory_DeclaredProtectionWins(t *testing.T) {
	t.Parallel()
	// Two sites both route 10.0.0.0/8 inward; only the declaration tells
	// which one protects 10.1.0.0/16.
	siteA, _ := newFirewall([]link{{"a0", "wan", "192.0.2.2/30"}, {"a1", "lan", "10.1.0.1/24"}},
		[]route{{"0.0.0.0/0", "192.0.2.1"}, {"10.0.0.0/8", "10.1.0.254"}},
		firemon.SecurityRule{ID: "out", Action: firemon.ActionPermit})
	siteB, _ := newFirewall([]link{{"b0", "wan", "198.51.100.2/30"}, {"b1", "lan", "10.2.0.1/24"}},
		[]route{{"0.0.0.0/0", "198.51.100.1"}, {"10.0.0.0/8", "10.2.0.254"}})
	inv, err := inventory.New([]inventory.Member{{Name: "a", Firewall: siteA}, {Name: "b", Firewall: siteB}},
		inventory.Options{Now: func() time.Time { return now }, Protections: []inventory.Protection{
			{Firewall: "a", Zone: "lan", Networks: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}},
			{Firewall: "b", Zone: "lan", Networks: []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}},
		}})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := inv.Locate(request("10.1.5.5, 172.31.0.1", "203.0.113.208", "tcp/443"))
	if err != nil {
		t.Fatal(err)
	}
	if got := names(tr); !slices.Equal(got, []string{"a(lan>wan)"}) || tr.Crossings[0].Ownership != inventory.OwnershipDeclared {
		t.Fatalf("crossings %v", got)
	}
	if tr.Excluded.Src.String() != "172.31.0.1" || tr.Excluded.Dst.String() != "203.0.113.208" {
		t.Fatalf("addresses no firewall owns must be excluded: %+v", tr.Excluded)
	}
}

func TestInventory_ClusterEvaluatedOnce(t *testing.T) {
	t.Parallel()
	fw, _ := newFirewall([]link{{"x0", "wan", "192.0.2.2/30"}, {"x1", "lan", "10.1.0.1/24"}},
		[]route{{"0.0.0.0/0", "192.0.2.1"}})
	inv, err := inventory.New([]inventory.Member{{Name: "fw1", Cluster: "site", Firewall: fw}, {Name: "fw2", Cluster: "site", Firewall: fw}},
		inventory.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	tr, _ := inv.Locate(request("10.1.0.5", "203.0.113.208", "tcp/443"))
	if len(tr.Crossings) != 1 || tr.Crossings[0].Firewall != "fw1" || !slices.Equal(tr.Crossings[0].Members, []string{"fw1", "fw2"}) {
		t.Fatalf("crossings %+v", tr.Crossings)
	}
}

func TestDevice_Label(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		d    inventory.Device
		want string
	}{
		{inventory.Device{Name: "SZX9-IN-FW01-10.251.8.203", Host: "10.251.8.203"}, "SZX9-IN-FW01(10.251.8.203)"},
		{inventory.Device{Name: "SZX9-IN-FW01-10.251.8.203"}, "SZX9-IN-FW01(10.251.8.203)"},
		{inventory.Device{Name: "edge1", Host: "192.0.2.1"}, "edge1(192.0.2.1)"},
		{inventory.Device{Name: "edge1"}, "edge1"},
	} {
		if got := tt.d.Label(); got != tt.want {
			t.Errorf("%+v: got %q, want %q", tt.d, got, tt.want)
		}
	}
}
