package inventory_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/inventory"
)

// bridge builds a transparent firewall: two layer-2 zones with one port
// each, management routing only, and rules between the zones.
func bridge(t *testing.T, rules ...firemon.SecurityRule) *firemon.Firewall {
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
			{Name: "x24", Zone: "l2-trust"}, {Name: "x25", Zone: "l2-untrust"},
			{Name: "MGT0", Zone: "mgt", VirtualRouter: "mgt-vr", Addresses: []netip.Prefix{netip.MustParsePrefix("10.251.8.203/24")}},
		},
		Routes: []firemon.Route{{VirtualRouter: "mgt-vr", Destination: netip.MustParsePrefix("0.0.0.0/0"), NextHop: netip.MustParseAddr("10.251.8.1")}},
		Rules:  rules,
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestTransparentClusters_ProtectedZonesLocateBothSides(t *testing.T) {
	t.Parallel()
	permit := firemon.SecurityRule{ID: "1", Action: firemon.ActionPermit, From: []string{"l2-untrust"}, To: []string{"l2-trust"}}
	out := firemon.SecurityRule{ID: "2", Action: firemon.ActionPermit, From: []string{"l2-trust"}, To: []string{"l2-untrust"}}
	members := []inventory.Member{
		{Name: "szx9-in-fw02", Cluster: "SZX9-IN", Firewall: bridge(t)}, // backup: no rules
		{Name: "szx9-in-fw01", Cluster: "SZX9-IN", Firewall: bridge(t, permit, out), Active: true},
		{Name: "szx8-in-fw01", Cluster: "SZX8-IN", Firewall: bridge(t, permit, out), Active: true},
		{Name: "szx8-in-fw02", Cluster: "SZX8-IN", Firewall: bridge(t)},
	}
	prot := func(fw string, nets ...string) inventory.Protection {
		p := inventory.Protection{Firewall: fw, Zone: "l2-trust"}
		for _, n := range nets {
			p.Networks = append(p.Networks, netip.MustParsePrefix(n))
		}
		return p
	}
	protections := []inventory.Protection{prot("szx9-in-fw01", "10.250.0.0/16", "10.254.0.0/16"), prot("szx8-in-fw01", "10.248.0.0/16")}
	// Without a binding for the far side a transparent firewall cannot
	// tell where the other end is, and says so.
	bare, err := inventory.New(members, inventory.Options{Now: func() time.Time { return now }, Protections: protections})
	if err != nil {
		t.Fatal(err)
	}
	if tr, err := bare.Locate(request("10.248.30.5", "10.250.116.25", "tcp/9600")); err != nil || len(tr.Crossings) != 0 || len(tr.ZonesNeeded) != 2 {
		t.Fatalf("far side unbound: %v %v zones needed %v", names(tr), err, tr.ZonesNeeded)
	}
	untrust := func(fw string) inventory.ZoneBinding {
		return inventory.ZoneBinding{Firewall: fw, Zone: "l2-untrust", Networks: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	}
	inv, err := inventory.New(members, inventory.Options{
		Now:         func() time.Time { return now },
		Protections: protections,
		Zones:       []inventory.ZoneBinding{untrust("szx9-in-fw01"), untrust("szx8-in-fw01")},
	})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := inv.Locate(request("10.248.30.5", "10.250.116.25", "tcp/9600"))
	if err != nil {
		t.Fatal(err)
	}
	got := names(tr)
	want := []string{"szx8-in-fw01(l2-trust>l2-untrust)", "szx9-in-fw01(l2-untrust>l2-trust)"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] || tr.Verdict.String() != "allowed" {
		t.Fatalf("each cluster on its active member, the far end through its bound zone: %v %s", got, tr.Verdict)
	}
	same, err := inv.Locate(request("10.250.1.1", "10.254.1.1", "tcp/22"))
	if err != nil {
		t.Fatal(err)
	}
	if len(same.Crossings) != 0 || len(same.Inside) != 1 || same.Inside[0].Zone != "l2-trust" {
		t.Fatalf("both ends behind l2-trust do not cross: %+v", same)
	}
}

func TestInventory_PlanOnlyCrossedParts(t *testing.T) {
	t.Parallel()
	members := []inventory.Member{
		{Name: "szx9-in-fw01", Cluster: "SZX9-IN", Firewall: bridge(t), Active: true},
		{Name: "szx8-in-fw01", Cluster: "SZX8-IN", Firewall: bridge(t), Active: true},
	}
	inv, err := inventory.New(members, inventory.Options{
		Now: func() time.Time { return now },
		Protections: []inventory.Protection{
			{Firewall: "szx9-in-fw01", Zone: "l2-trust", Networks: []netip.Prefix{netip.MustParsePrefix("10.250.0.0/16"), netip.MustParsePrefix("10.254.0.0/16")}},
			{Firewall: "szx8-in-fw01", Zone: "l2-trust", Networks: []netip.Prefix{netip.MustParsePrefix("10.248.0.0/16")}},
		},
		Zones: []inventory.ZoneBinding{
			{Firewall: "szx9-in-fw01", Zone: "l2-untrust", Networks: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
			{Firewall: "szx8-in-fw01", Zone: "l2-untrust", Networks: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := request("10.250.1.0/24,10.248.1.0/24", "10.254.1.1", "tcp/22")
	plans, err := inv.Plan(design.Intent{Src: req.Src, Dst: req.Dst, Service: req.Service, Name: "req"})
	if err != nil {
		t.Fatal(err)
	}
	inside := netip.MustParseAddr("10.250.1.1")
	if len(plans) == 0 {
		t.Fatal("the crossing part needs a design")
	}
	for _, p := range plans {
		if p.Part.Src.Contains(inside) {
			t.Fatalf("%s designs traffic that stays behind l2-trust: %v", p.Cluster, p.Part.Src)
		}
	}
}
