package report_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/report"
	"github.com/gatework/firemon/traffic"
)

var now = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func inline(s string) []firemon.AddressRef {
	return []firemon.AddressRef{firemon.InlineAddress(firemon.PrefixEntry(prefix(s)))}
}

func site(rules ...firemon.SecurityRule) *firemon.Firewall {
	cfg := &firemon.Config{
		Vendor:         firemon.VendorPaloAlto,
		Semantics:      firemon.Semantics{InterzoneAction: firemon.ActionDeny, IntrazoneAction: firemon.ActionPermit, DefaultVirtualRouter: "vr"},
		VirtualRouters: []firemon.VirtualRouter{{Name: "vr"}},
		Zones:          []firemon.Zone{{Name: "lan"}, {Name: "wan"}},
		Interfaces: []firemon.Interface{
			{Name: "e0", Zone: "wan", VirtualRouter: "vr", Addresses: []netip.Prefix{prefix("203.0.113.2/30")}},
			{Name: "e1", Zone: "lan", VirtualRouter: "vr", Addresses: []netip.Prefix{prefix("10.1.0.1/16")}},
		},
		Routes: []firemon.Route{{VirtualRouter: "vr", Destination: prefix("0.0.0.0/0"), NextHop: netip.MustParseAddr("203.0.113.1")}},
		Services: []firemon.Service{
			{Name: "https", Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(443))}},
			{Name: "ssh", Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(22))}},
		},
		Rules: rules,
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		panic(err)
	}
	return fw
}

func build(t *testing.T, fw *firemon.Firewall, src, dst, svc string, withPlan bool) report.Report {
	t.Helper()
	inv, err := inventory.New([]inventory.Member{{Name: "fw", Firewall: fw}}, inventory.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := traffic.ParseAddressSet(src)
	d, _ := traffic.ParseAddressSet(dst)
	v, _ := traffic.ParseServiceSet(svc)
	tr, err := inv.Locate(query.Request{Src: s, Dst: d, Service: v})
	if err != nil {
		t.Fatal(err)
	}
	var plans []inventory.ClusterPlan
	if withPlan {
		if plans, err = inv.Plan(design.Intent{Src: s, Dst: d, Service: v, Name: "req"}); err != nil {
			t.Fatal(err)
		}
	}
	return report.Build(nil, tr, map[string]*firemon.Firewall{"fw": fw}, plans)
}

func rule(id string, action firemon.Action, from, to string, src, dst string, services ...string) firemon.SecurityRule {
	r := firemon.SecurityRule{ID: id, Name: id, Action: action, Services: services}
	if from != "" {
		r.From, r.To = []string{from}, []string{to}
	}
	if src != "" {
		r.Source = inline(src)
	}
	if dst != "" {
		r.Destination = inline(dst)
	}
	return r
}

func TestBuild_Statuses(t *testing.T) {
	t.Parallel()
	p, d := firemon.ActionPermit, firemon.ActionDeny
	tests := []struct {
		name string
		fw   *firemon.Firewall
		want report.Status
	}{
		{"full match", site(rule("web", p, "lan", "wan", "10.1.0.0/16", "", "https")), report.StatusFullMatch},
		{"partial match", site(rule("web", p, "lan", "wan", "10.1.0.0/24", "", "https")), report.StatusPartialMatch},
		{"need new", site(), report.StatusNeedNew},
		{"blocked", site(rule("no", d, "lan", "wan", "10.1.0.0/16", "8.8.8.8/32")), report.StatusBlocked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := build(t, tt.fw, "10.1.0.0/23", "8.8.8.8", "tcp/443", false)
			if len(r.Firewalls) != 1 || r.Firewalls[0].Status != tt.want || r.Status != tt.want {
				t.Fatalf("got %+v", r.Firewalls)
			}
		})
	}
}

func TestBuild_CandidatesRankSafeExtensionsFirst(t *testing.T) {
	t.Parallel()
	p := firemon.ActionPermit
	fw := site(
		rule("broad", p, "", "", "10.1.0.0/16", "", "ssh"),                   // zone any, other service
		rule("exact", p, "lan", "wan", "10.1.0.5/32", "8.8.8.8/32", "https"), // lacks only sources
		rule("wide", p, "lan", "wan", "10.1.0.6/32", "", "https"),            // destination any: wider than the request
	)
	r := build(t, fw, "10.1.0.7", "8.8.8.8", "tcp/443", true)
	f := r.Firewalls[0]
	if f.Status != report.StatusNeedNew || len(f.Candidates) == 0 {
		t.Fatalf("firewall %+v", f)
	}
	best := f.Candidates[0]
	if best.Rule != "exact" || !best.Extendable || !best.Recommended || best.Covers != 2 {
		t.Fatalf("best candidate %+v (all %+v)", best, f.Candidates)
	}
	for _, c := range f.Candidates[1:] {
		if c.Extendable {
			t.Errorf("candidate %s should carry a reason: %+v", c.Rule, c)
		}
	}
}
