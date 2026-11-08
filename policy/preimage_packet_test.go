package policy_test

import (
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func preimageData(vendor string) fm.Data {
	d := migrationData(vendor)
	d.StaticNATs[0].ID, d.StaticNATs[0].Source = "published", nil
	d.StaticNATs[0].Destination = []fm.Mapping{{Original: rangeOf("198.51.100.10/31"), Translated: rangeOf("198.51.100.30/31"), Mode: fm.Offset}}
	d.StaticNATs[0].DestinationPorts = []fm.PortMapping{{Original: flow.Interval{Low: 443, High: 443}, Translated: flow.Interval{Low: 8443, High: 8443}, Mode: fm.Offset}}
	d.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "first"}, Ranges: []flow.AddressRange{rangeOf("198.51.100.30/32")}}}
	first, rest := d.Rules[0], d.Rules[0]
	first.Position = 1
	first.Match.AnyDestination = false
	first.Match.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "first"}}
	rest.ID, rest.Position, rest.Action = "deny", 2, fm.Deny
	d.Rules = []fm.RuleRecord{first, rest}
	return d
}

func TestOriginalTrafficRetainsDeniedDestinationLookup(t *testing.T) {
	for _, vendor := range []string{"huawei", "srx"} {
		t.Run(vendor, func(t *testing.T) {
			d := preimageData(vendor)
			d.StaticNATs[0].Order.Section = "nat-server"
			if vendor == "srx" {
				d.StaticNATs[0].Order.Section = "static:published"
				d.StaticNATs[0].Bidirectional = true
				d.StaticNATs[0].Match.AnyFromZone = false
				d.StaticNATs[0].Match.FromZones = []fm.ID{"inside"}
			}
			fw := migrationGraph(t, d)
			q := migrationRequest(t)
			q.Traffic = preimageTraffic(t, preimagePacket("192.0.2.1", "198.51.100.10", 443), preimagePacket("192.0.2.1", "198.51.100.11", 443))
			result, err := (policy.Engine{}).QueryPacket(t.Context(), fw, q)
			if err != nil || !result.Complete || len(result.Paths) != 2 {
				t.Fatal(result, err)
			}
			var covered flow.Traffic
			for _, path := range result.Paths {
				if len(path.PolicyNAT) != 1 || len(path.Policy.Decisions) != 1 {
					t.Fatal("lookup stage missing", path)
				}
				decision := path.Policy.Decisions[0]
				if vendor == "huawei" && decision.Action == fm.Deny && len(path.NAT.Steps) != 0 {
					t.Fatal("denied policy applied post-policy NAT", path)
				}
				got, err := (policy.Engine{}).OriginalTraffic(t.Context(), fw, path, decision.Traffic)
				assertPreimage(t, got, path.Original, err)
				want := "198.51.100.10"
				if decision.Action == fm.Deny {
					want = "198.51.100.11"
				}
				assertPreimage(t, got, preimageTraffic(t, preimagePacket("192.0.2.1", want, 443)), nil)
				covered, err = covered.Union(got, 4096)
				if err != nil {
					t.Fatal(err)
				}
			}
			assertPreimage(t, covered, q.Traffic, nil)
			if vendor == "srx" {
				proof, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), fw, fw, q, q)
				if err != nil || proof.Partitions != 2 {
					t.Fatal("real destination/port policy effects lost original ownership", proof, err)
				}
				d.Rules[0].LogStart = fm.Known
				if _, err := (policy.Engine{}).EquivalentPacketEffects(t.Context(), fw, migrationGraph(t, d), q, q); !errors.Is(err, policy.ErrNotEquivalent) {
					t.Fatal("changed real-coordinate rule effect passed wire equivalence", err)
				}
			}
			result.Paths[0].PolicyNAT[0].ID = "mutated"
			if result.Paths[1].PolicyNAT[0].ID != "published" {
				t.Fatal("lookup step slices are shared between paths")
			}
			for _, path := range result.Paths {
				for _, step := range path.NAT.Steps {
					if step.ID != "published" {
						t.Fatal("lookup mutation changed final NAT evidence")
					}
				}
			}
		})
	}
}

func TestOriginalTrafficUsesFortinetPolicyCoordinates(t *testing.T) {
	d := preimageData("fortinet")
	d.StaticNATs[0].Order.Section = "vip"
	d.Addresses[0].Ranges = []flow.AddressRange{rangeOf("198.51.100.10/31")}
	d.Addresses[0].VIP = fm.NATRef{Kind: fm.StaticNATObject, ID: "published"}
	d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: "client"}, Ranges: []flow.AddressRange{rangeOf("192.0.2.0/32")}})
	d.Rules[0].Match.AnySource = false
	d.Rules[0].Match.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "client"}}
	d.Rules[1].Match.AnyDestination = false
	d.Rules[1].Match.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "first"}}
	d.Rules[1].MatchVIP = fm.Known
	fw := migrationGraph(t, d)
	q := migrationRequest(t)
	a, b := preimagePacket("192.0.2.0", "198.51.100.10", 443), preimagePacket("192.0.2.1", "198.51.100.11", 443)
	q.Traffic = preimageTraffic(t, a, b)
	result, err := (policy.Engine{}).QueryPacket(t.Context(), fw, q)
	if err != nil || !result.Complete || len(result.Paths) != 2 {
		t.Fatal(result, err)
	}
	for _, path := range result.Paths {
		if len(path.PolicyNAT) != 1 || len(path.NativeRequests) != 1 || len(path.Policy.Decisions) != 1 {
			t.Fatal("missing native packet views", path)
		}
		assertPreimage(t, path.NativeRequests[0].Traffic, path.Original, nil)
		decision := path.Policy.Decisions[0]
		if same, err := decision.Traffic.Equal(path.Original, 4096); err != nil || same {
			t.Fatal("fixture must distinguish engine query and policy coordinates", err)
		}
		got, err := (policy.Engine{}).OriginalTraffic(t.Context(), fw, path, decision.Traffic)
		assertPreimage(t, got, path.Original, err)
	}
	result.Paths[0].PolicyNAT[0].ID = "mutated"
	if result.Paths[0].NAT.Steps[0].ID != "published" || result.Paths[1].PolicyNAT[0].ID != "published" {
		t.Fatal("lookup mutation changed another packet view")
	}
}
