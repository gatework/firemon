package firemon_test

import (
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func rng(a, b string) flow.Range {
	return flow.Range{First: netip.MustParseAddr(a), Last: netip.MustParseAddr(b)}
}

func TestInvalidZoneRelationRemainsIncomplete(t *testing.T) {
	d := fm.Data{Rules: []fm.RuleRecord{{Object: fm.Object{ID: "rule"}, Action: fm.Permit, RuleSet: "security", Match: fm.Match{ZoneRelation: fm.ZoneRelation(255), AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}}}
	d.Metadata = fm.Metadata{Device: "test", Vendor: "paloalto"}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if fw.Complete() {
		t.Fatal("unknown zone relation was declared complete")
	}
}
func seed() fm.Data {
	return fm.Data{
		Metadata: fm.Metadata{Device: "test", Vendor: "hillstone", ParserVersion: "1"},
		Zones:    []fm.ZoneRecord{{Object: fm.Object{ID: "inside"}}, {Object: fm.Object{ID: "outside"}}},
		Interfaces: []fm.InterfaceRecord{
			{Object: fm.Object{ID: "eth0", Scope: "vr1"}, Zone: "inside", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}},
			{Object: fm.Object{ID: "eth1", Scope: "vr1"}, Zone: "outside", Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.129/25")}},
		},
		Routes:        []fm.RouteRecord{{Object: fm.Object{ID: "default", Scope: "vr1"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), NextHop: netip.MustParseAddr("192.0.2.200")}},
		Addresses:     []fm.AddressRecord{{Object: fm.Object{ID: "host"}, Ranges: []flow.Range{rng("192.0.2.10", "192.0.2.10")}}},
		AddressGroups: []fm.AddressGroupRecord{{Object: fm.Object{ID: "group"}, Members: []fm.AddressRef{{Kind: fm.AddressObject, ID: "host"}}}},
		StaticNATs:    []fm.StaticNATRecord{{Object: fm.Object{ID: "static"}, Order: fm.NATOrder{Stage: 1, Position: 2}, Source: []fm.Mapping{{Original: rng("192.0.2.0", "192.0.2.255"), Translated: rng("203.0.113.0", "203.0.113.255"), Mode: fm.Offset}}}},
		NATPools:      []fm.NATPoolRecord{{Object: fm.Object{ID: "pool"}, Ranges: []flow.Range{rng("203.0.113.1", "203.0.113.5")}}},
		DynamicNATs:   []fm.DynamicNATRecord{{Object: fm.Object{ID: "dynamic"}, Order: fm.NATOrder{Stage: 1, Position: 1}, SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation, SourcePool: "pool"}},
	}
}
func TestSealBindsRouteToLongestPrefixAndPreservesSharedObjects(t *testing.T) {
	data := seed()
	fw, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	r := fw.Route("default")
	if r.Interface() != fw.Interface("eth1") {
		t.Fatalf("wrong longest prefix binding: %v", r.Interface())
	}
	if r.Interface().Zone() != fw.Zone("outside") {
		t.Fatal("zone reference not shared")
	}
	if fw.AddressGroup("group").Addresses()[0] != fw.Address("host") {
		t.Fatal("address reference not shared")
	}
	if fw.DynamicNAT("dynamic").SourcePool() != fw.NATPool("pool") {
		t.Fatal("pool reference not shared")
	}
	if got := fw.NATSequence(); len(got) != 2 || got[0].Kind != fm.DynamicNATObject || got[1].Kind != fm.StaticNATObject {
		t.Fatal(got)
	}
	data.Interfaces[1].Addresses[0] = netip.MustParsePrefix("10.0.0.1/24")
	exported := fw.Export()
	exported.Interfaces[1].Addresses[0] = netip.MustParsePrefix("10.1.0.1/24")
	if got := fw.Interface("eth1").Record().Addresses[0]; got.String() != "192.0.2.129/25" {
		t.Fatal("mutable graph", got)
	}
}
func TestAmbiguousOrCrossVRFRouteNeverGetsArbitraryInterface(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*fm.Data)
	}{
		{"ambiguous", func(d *fm.Data) { i := d.Interfaces[1]; i.ID = "eth2"; d.Interfaces = append(d.Interfaces, i) }},
		{"cross-vrf", func(d *fm.Data) { d.Routes[0].Scope = "vr2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := seed()
			tc.edit(&d)
			fw, err := fm.Seal(d)
			if err != nil {
				t.Fatal(err)
			}
			if fw.Route("default").Interface() != nil || fw.Complete() {
				t.Fatal("unproven route considered complete")
			}
		})
	}
}
func TestGroupCyclesAndMissingMembersRemainIncomplete(t *testing.T) {
	d := seed()
	d.AddressGroups[0].Members = append(d.AddressGroups[0].Members, fm.AddressRef{Kind: fm.AddressGroupObject, ID: "group"}, fm.AddressRef{Kind: fm.AddressObject, ID: "missing"})
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if fw.Complete() || len(fw.Diagnostics()) < 2 {
		t.Fatal("missing evidence lost", fw.Diagnostics())
	}
}
func TestStaticNATRejectsInvalidOffsetAndDoesNotGuessUnknown(t *testing.T) {
	d := seed()
	d.StaticNATs[0].Source[0].Translated.Last = netip.MustParseAddr("203.0.113.1")
	if _, err := fm.Seal(d); err == nil {
		t.Fatal("unequal offset accepted")
	}
	d = seed()
	d.StaticNATs[0].Source[0].Mode = fm.UnknownMapping
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if fw.Complete() {
		t.Fatal("unknown mapping became exact")
	}
}
func TestSemanticDigestIgnoresDeclarationOrderButIncludesNativeOrder(t *testing.T) {
	d := seed()
	a, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Interfaces[0], d.Interfaces[1] = d.Interfaces[1], d.Interfaces[0]
	b, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if a.SemanticDigest() != b.SemanticDigest() {
		t.Fatal("declaration order changed meaning")
	}
	d.StaticNATs[0].Order.Position = 0
	c, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if a.SemanticDigest() == c.SemanticDigest() {
		t.Fatal("NAT order absent from digest")
	}
}

func TestNATConflictingMappingsAndMissingAllocationStayUnsafe(t *testing.T) {
	t.Run("conflicting static mapping", func(t *testing.T) {
		d := seed()
		m := d.StaticNATs[0].Source[0]
		m.Translated = rng("198.51.100.0", "198.51.100.255")
		d.StaticNATs[0].Source = append(d.StaticNATs[0].Source, m)
		if _, err := fm.Seal(d); err == nil {
			t.Fatal("conflicting forward function accepted")
		}
	})
	t.Run("dynamic allocation has no target", func(t *testing.T) {
		d := seed()
		d.DynamicNATs[0].SourcePool = ""
		fw, err := fm.Seal(d)
		if err != nil {
			t.Fatal(err)
		}
		if fw.Complete() {
			t.Fatal("missing allocation target considered complete")
		}
	})
}

func TestUnencodableScheduleCannotReceiveSemanticDigest(t *testing.T) {
	d := seed()
	d.Schedules = []fm.ScheduleRecord{{Object: fm.Object{ID: "invalid-year"}, Windows: []fm.TimeWindow{{Start: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(10000, 1, 2, 0, 0, 0, 0, time.UTC)}}}}
	if _, err := fm.Seal(d); err == nil {
		t.Fatal("invalid canonical time silently hashed as empty payload")
	}
}

func TestSourceDigestMustDescribeTheRetainedRawConfiguration(t *testing.T) {
	d := seed()
	d.Raw = "retained config"
	d.Metadata.SourceDigest = strings.Repeat("0", 64)
	if _, err := fm.Seal(d); err == nil {
		t.Fatal("snapshot source identity disagrees with raw configuration")
	}
}

func TestTypedNATMatchesReferenceTheSameCatalogObjects(t *testing.T) {
	d := seed()
	ref := fm.AddressRef{Kind: fm.AddressObject, ID: "host"}
	d.StaticNATs[0].Match.Sources = []fm.AddressRef{ref}
	d.DynamicNATs[0].Match.Sources = []fm.AddressRef{ref}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if fw.StaticNAT("static").Match().Sources()[0] != fw.Address("host") || fw.DynamicNAT("dynamic").Match().Sources()[0] != fw.Address("host") {
		t.Fatal("NAT match detached from object catalog")
	}
	references := fw.StaticNAT("static").Match().Sources()
	references[0] = nil
	if fw.StaticNAT("static").Match().Sources()[0] == nil {
		t.Fatal("mutable NAT references escaped")
	}
}
