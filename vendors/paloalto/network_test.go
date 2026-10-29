package paloalto_test

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors/paloalto"
)

func routeFor(t *testing.T, fw *fm.Firewall, vrf, name string) *fm.Route {
	t.Helper()
	var found *fm.Route
	for _, route := range fw.Routes() {
		r := route.Record()
		if r.Scope == vrf && r.Name == name {
			if found != nil {
				t.Fatal("duplicate native route identity", vrf, name)
			}
			found = route
		}
	}
	if found == nil {
		t.Fatal("missing native route", vrf, name)
	}
	return found
}

func TestStaticRoutesKeepVirtualRouterNamespaceThroughSnapshot(t *testing.T) {
	var raw strings.Builder
	for i, vrf := range []string{"vr-a", "vr-b"} {
		fmt.Fprintf(&raw, "set network interface ethernet ethernet1/%d layer3 ip 192.0.2.%d/24\n", i+1, i+1)
		fmt.Fprintf(&raw, "set network virtual-router %s interface ethernet1/%d\n", vrf, i+1)
		fmt.Fprintf(&raw, "set zone zone-%d network layer3 ethernet1/%d\n", i, i+1)
		fmt.Fprintf(&raw, "set network virtual-router %s routing-table ip static-route default destination 0.0.0.0/0\n", vrf)
		fmt.Fprintf(&raw, "set network virtual-router %s routing-table ip static-route default nexthop ip-address 192.0.2.%d\n", vrf, 254-i)
	}
	fw, err := paloalto.Parse(context.Background(), config.Source{Text: raw.String(), Complete: true}, fm.Metadata{Device: "pan"})
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	var data bytes.Buffer
	if err := snapshot.Encode(&data, fw); err != nil {
		t.Fatal(err)
	}
	loaded, err := snapshot.Decode(&data, snapshot.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, graph := range []*fm.Firewall{fw, loaded} {
		a, b := routeFor(t, graph, "vr-a", "default"), routeFor(t, graph, "vr-b", "default")
		if a.ID() == b.ID() || a.Record().NextHop.String() != "192.0.2.254" || b.Record().NextHop.String() != "192.0.2.253" {
			t.Fatal("cross-router route contamination", a.Record(), b.Record())
		}
		for i, vrf := range []string{"vr-a", "vr-b"} {
			dest := netip.MustParseAddr("203.0.113.10")
			addresses, _ := flow.NewAddressSet(flow.AddressRange{First: dest, Last: dest})
			paths, err := (policy.Engine{Limits: policy.Limits{MaxRegions: 16}}).ResolveRoutes(context.Background(), graph, vrf, addresses)
			want := graph.Interface(fm.ID(fmt.Sprintf("ethernet1/%d", i+1)))
			if err != nil || len(paths) != 1 || !paths[0].Known || paths[0].Interface != want {
				t.Fatal("route bound across VRF", vrf, paths, err)
			}
		}
	}
}
