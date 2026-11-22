package inventory_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// natLab: the edge publishes 203.0.113.10:443 as 10.2.0.9:8443, a server
// behind core. Core only sees the translated packet.
func natLab(t *testing.T, coreRules ...firemon.SecurityRule) *inventory.Inventory {
	t.Helper()
	core := firewall(t,
		[]link{{"c0", "transit", "10.0.0.2/30"}, {"c1", "users", "10.1.0.1/16"}, {"c2", "servers", "10.2.0.1/16"}},
		[]route{{"0.0.0.0/0", "10.0.0.1"}}, coreRules...)
	cfg := edgeConfig()
	cfg.DynamicNATs = []firemon.DynamicNAT{{
		ID: "pub", From: []string{"internet"}, Destination: []firemon.AddressRef{firemon.InlineAddress(firemon.HostEntry(netip.MustParseAddr("203.0.113.10")))},
		Services: []string{"any"},
		TranslatedDestination: firemon.Translation{Mode: firemon.TranslationModeAddress,
			Addresses: []firemon.AddressRef{firemon.InlineAddress(firemon.HostEntry(netip.MustParseAddr("10.2.0.9")))}, Port: 8443},
	}}
	cfg.Rules = []firemon.SecurityRule{{ID: "in", From: []string{"internet"}, To: []string{"inside"}, Action: firemon.ActionPermit}}
	edge, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.New([]inventory.Member{{Name: "core", Firewall: core}, {Name: "edge", Firewall: edge}}, inventory.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func edgeConfig() *firemon.Config {
	return &firemon.Config{
		Vendor:         firemon.VendorPaloAlto,
		Semantics:      firemon.Semantics{InterzoneAction: firemon.ActionDeny, IntrazoneAction: firemon.ActionPermit, DefaultVirtualRouter: "vr", PolicyDestination: firemon.AddressStageOriginal},
		VirtualRouters: []firemon.VirtualRouter{{Name: "vr"}},
		Zones:          []firemon.Zone{{Name: "internet"}, {Name: "inside"}},
		Interfaces: []firemon.Interface{
			{Name: "e0", Zone: "internet", VirtualRouter: "vr", Addresses: []netip.Prefix{netip.MustParsePrefix("203.0.113.2/28")}},
			{Name: "e1", Zone: "inside", VirtualRouter: "vr", Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/30")}},
		},
		Routes: []firemon.Route{
			{VirtualRouter: "vr", Destination: netip.MustParsePrefix("0.0.0.0/0"), NextHop: netip.MustParseAddr("203.0.113.1")},
			{VirtualRouter: "vr", Destination: netip.MustParsePrefix("10.0.0.0/8"), NextHop: netip.MustParseAddr("10.0.0.2")},
		},
		Services: []firemon.Service{{Name: "any", Predefined: true, Entries: []firemon.ServiceEntry{{AnyProtocol: true}}}},
	}
}

func TestLocate_HandsTranslatedTrafficOn(t *testing.T) {
	t.Parallel()
	toServer := firemon.SecurityRule{ID: "srv", From: []string{"transit"}, To: []string{"servers"}, Action: firemon.ActionPermit,
		Destination:    []firemon.AddressRef{firemon.InlineAddress(firemon.HostEntry(netip.MustParseAddr("10.2.0.9")))},
		ServiceEntries: []firemon.ServiceEntry{firemon.PortEntry(6, portRange(8443))}}
	for _, tt := range []struct {
		name  string
		rules []firemon.SecurityRule
		want  query.Verdict
	}{
		{"core permits the translated server port", []firemon.SecurityRule{toServer}, query.VerdictAllowed},
		{"core denies it by default", nil, query.VerdictPartial},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tr, err := natLab(t, tt.rules...).Locate(request("198.51.100.5", "203.0.113.10", "tcp/443"))
			if err != nil {
				t.Fatal(err)
			}
			var core *inventory.Crossing
			for i := range tr.Crossings {
				if tr.Crossings[i].Cluster == "core" {
					core = &tr.Crossings[i]
				}
			}
			if core == nil {
				t.Fatalf("core not reached through NAT: %v", names(tr))
			}
			if len(core.Upstream) != 1 || core.Upstream[0].Cluster != "edge" {
				t.Fatalf("upstream %+v", core.Upstream)
			}
			p := core.Paths[0]
			if p.Original.Dst.String() != "10.2.0.9" || p.Original.Service.String() != "tcp/8443" || p.From != "transit" || p.To != "servers" {
				t.Fatalf("core evaluated %s %s->%s", p.Original, p.From, p.To)
			}
			if core.Seq <= seqOf(tr, "edge") {
				t.Fatalf("core seq %d after edge %d", core.Seq, seqOf(tr, "edge"))
			}
			if tr.Verdict != tt.want {
				t.Fatalf("verdict %s, want %s", tr.Verdict, tt.want)
			}
		})
	}
}

// Without NAT the chain changes nothing but the order.
func TestLocate_ChainKeepsUntranslatedTraffic(t *testing.T) {
	t.Parallel()
	webOut := firemon.SecurityRule{ID: "web", From: []string{"users"}, To: []string{"transit"}, Action: firemon.ActionPermit}
	tr, err := lab(t, webOut).Locate(request("10.1.0.5", "203.0.113.208", "tcp/443"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tr.Crossings {
		if len(c.Upstream) != 0 {
			t.Fatalf("%s has upstream %+v", c.Cluster, c.Upstream)
		}
	}
	if seqOf(tr, "core") >= seqOf(tr, "edge") {
		t.Fatalf("core %d must come before edge %d", seqOf(tr, "core"), seqOf(tr, "edge"))
	}
}

func seqOf(tr inventory.Trace, cluster string) int {
	for _, c := range tr.Crossings {
		if c.Cluster == cluster {
			return c.Seq
		}
	}
	return -1
}

func portRange(p uint16) traffic.PortRange { return traffic.Port(p) }

// The firewall behind the NAT is planned for the server it really sees.
func TestPlan_DesignsTranslatedTraffic(t *testing.T) {
	t.Parallel()
	inv := natLab(t)
	r := request("198.51.100.5", "203.0.113.10", "tcp/443")
	plans, err := inv.Plan(design.Intent{Src: r.Src, Dst: r.Dst, Service: r.Service, Name: "T1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, cp := range plans {
		if cp.Cluster != "core" {
			continue
		}
		if !cp.Plan.Verified {
			t.Fatalf("core plan not verified: %s", cp.Plan.VerifyError)
		}
		for _, c := range cp.Plan.Changes {
			if a, ok := c.(design.AddRule); ok {
				got := a.Rule.Destination[0].String() + " " + a.Rule.Services[0]
				if !strings.Contains(got, "10.2.0.9") || !strings.Contains(got, "8443") {
					t.Fatalf("core rule for %s", got)
				}
				return
			}
		}
		t.Fatalf("no rule on core: %v", cp.Plan.Changes)
	}
	t.Fatal("core not planned")
}
