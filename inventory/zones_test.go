package inventory_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/inventory"
)

// threeZoneBridge is a transparent firewall with three layer-2 zones: the
// peer of the protected zone is not unique, so only zone bindings locate
// the far end.
func threeZoneBridge(t *testing.T) *firemon.Firewall {
	t.Helper()
	cfg := &firemon.Config{
		Vendor:         firemon.VendorHillstone,
		Semantics:      firemon.Semantics{InterzoneAction: firemon.ActionDeny, IntrazoneAction: firemon.ActionDeny, DefaultVirtualRouter: "mgt-vr"},
		VirtualRouters: []firemon.VirtualRouter{{Name: "mgt-vr"}},
		Zones: []firemon.Zone{
			{Name: "l2-trust", Mode: firemon.ZoneModeLayer2}, {Name: "l2-untrust", Mode: firemon.ZoneModeLayer2},
			{Name: "l2-dmz", Mode: firemon.ZoneModeLayer2}, {Name: "mgt", Mode: firemon.ZoneModeLayer3, VirtualRouter: "mgt-vr"},
		},
		Interfaces: []firemon.Interface{
			{Name: "x24", Zone: "l2-trust"}, {Name: "x25", Zone: "l2-untrust"}, {Name: "x26", Zone: "l2-dmz"},
			{Name: "MGT0", Zone: "mgt", VirtualRouter: "mgt-vr", Addresses: []netip.Prefix{netip.MustParsePrefix("10.251.8.203/24")}},
		},
		Rules: []firemon.SecurityRule{
			{ID: "1", Action: firemon.ActionPermit, From: []string{"l2-trust"}, To: []string{"l2-dmz"}},
		},
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestInventory_ZoneBindingsLocateTheFarEnd(t *testing.T) {
	t.Parallel()
	pfx := func(s ...string) []netip.Prefix {
		out := make([]netip.Prefix, len(s))
		for i, x := range s {
			out[i] = netip.MustParsePrefix(x)
		}
		return out
	}
	members := []inventory.Member{{Name: "fw1", Firewall: threeZoneBridge(t), Active: true}}
	zones := []inventory.ZoneBinding{
		{Firewall: "fw1", Zone: "l2-trust", Networks: pfx("10.250.0.0/16"), Protected: true},
		{Firewall: "fw1", Zone: "l2-dmz", Networks: pfx("10.99.0.0/16")},
		{Firewall: "fw1", Zone: "l2-untrust", Networks: pfx("0.0.0.0/0")},
	}
	inv, err := inventory.New(members, inventory.Options{Now: func() time.Time { return now }, Zones: zones})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		dst, want, verdict string
	}{
		{"10.99.1.1", "fw1(l2-trust>l2-dmz)", "allowed"},
		{"203.0.113.208", "fw1(l2-trust>l2-untrust)", "denied"},
	} {
		tr, err := inv.Locate(request("10.250.1.1", tt.dst, "tcp/443"))
		if err != nil {
			t.Fatal(err)
		}
		if got := names(tr); len(got) != 1 || got[0] != tt.want || tr.Verdict.String() != tt.verdict {
			t.Errorf("to %s: %v %s, want %s %s", tt.dst, got, tr.Verdict, tt.want, tt.verdict)
		}
	}
	// An unprotected binding does not make the firewall own the address.
	tr, err := inv.Locate(request("10.99.1.1", "203.0.113.208", "tcp/443"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Crossings) != 0 || tr.Excluded.Src.IsEmpty() {
		t.Errorf("neither end protected: %v excluded %+v", names(tr), tr.Excluded)
	}
}

// Two parts crossing one firewall are designed as one change: numbered on,
// objects created once, and the whole change applies to the firewall.
func TestInventory_PlanAggregatesAFirewall(t *testing.T) {
	t.Parallel()
	fw := bridge(t)
	inv, err := inventory.New([]inventory.Member{{Name: "fw1", Firewall: fw, Active: true}}, inventory.Options{
		Now: func() time.Time { return now },
		Zones: []inventory.ZoneBinding{
			{Firewall: "fw1", Zone: "l2-trust", Networks: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/16")}, Protected: true},
			{Firewall: "fw1", Zone: "l2-untrust", Networks: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := request("10.250.1.1,203.0.113.209", "203.0.113.208,10.250.2.2", "tcp/443")
	plans, err := inv.Plan(design.Intent{Src: req.Src, Dst: req.Dst, Service: req.Service})
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || len(plans[0].Parts) != 2 {
		t.Fatalf("one plan for the firewall's two parts: %+v", plans)
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, c := range plans[0].Plan.Changes {
		if add, ok := c.(design.AddRule); ok {
			if ids[add.Rule.ID] || names[add.Rule.Name] {
				t.Fatalf("rule %s %s repeated: %v", add.Rule.ID, add.Rule.Name, plans[0].Plan.Changes)
			}
			ids[add.Rule.ID], names[add.Rule.Name] = true, true
		}
	}
	if len(ids) != 2 {
		t.Fatalf("a rule per direction: %v", plans[0].Plan.Changes)
	}
	cfg := fw.Config()
	if err := design.Apply(cfg, plans[0].Plan.Changes); err != nil {
		t.Fatalf("the change applies as one: %v", err)
	}
}

// Networks of equal length that different firewalls declare are not
// ambiguous; only addresses two firewalls both declare are.
func TestInventory_AmbiguousOnlyWhenShared(t *testing.T) {
	t.Parallel()
	bind := func(fw, n string) inventory.ZoneBinding {
		return inventory.ZoneBinding{Firewall: fw, Zone: "l2-trust", Networks: []netip.Prefix{netip.MustParsePrefix(n)}, Protected: true}
	}
	members := []inventory.Member{{Name: "a", Firewall: bridge(t)}, {Name: "b", Firewall: bridge(t)}}
	inv, err := inventory.New(members, inventory.Options{Now: func() time.Time { return now }, Zones: []inventory.ZoneBinding{bind("a", "10.248.0.0/16"), bind("b", "10.250.0.0/16"), bind("b", "10.99.0.0/24"), bind("a", "10.99.0.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := inv.Locate(request("10.248.1.1,10.250.1.1", "203.0.113.208", "tcp/443"))
	if err != nil || len(tr.Ambiguous) != 0 {
		t.Fatalf("different networks: ambiguous %v %v", tr.Ambiguous, err)
	}
	tr, err = inv.Locate(request("10.99.0.5", "203.0.113.208", "tcp/443"))
	if err != nil || len(tr.Ambiguous) != 1 || tr.Ambiguous[0] != "10.99.0.5" {
		t.Fatalf("a shared network: ambiguous %v %v", tr.Ambiguous, err)
	}
}
