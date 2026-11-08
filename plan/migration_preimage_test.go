package plan

import (
	"net/netip"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestMigrationNATDomainsRetainMixedSelectedOwnership(t *testing.T) {
	host := func(ip string) flow.AddressRange {
		a := netip.MustParseAddr(ip)
		return flow.AddressRange{First: a, Last: a}
	}
	anyMatch := fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
	selected := anyMatch
	selected.AnyDestination = false
	selected.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "selected-host"}}
	d := fm.Data{
		Metadata:   fm.Metadata{Device: "synthetic", Vendor: "paloalto", Software: "10.2.0"},
		Zones:      []fm.ZoneRecord{{Object: fm.Object{ID: "inside"}}, {Object: fm.Object{ID: "outside"}}},
		Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "egress"}, Zone: "outside", Addresses: []netip.Prefix{netip.MustParsePrefix("198.51.100.254/24")}}},
		Routes:     []fm.RouteRecord{{Object: fm.Object{ID: "default"}, Destination: netip.MustParsePrefix("0.0.0.0/0"), Interface: "egress"}},
		Addresses:  []fm.AddressRecord{{Object: fm.Object{ID: "selected-host"}, Ranges: []flow.AddressRange{host("198.51.100.10")}}},
		Rules: []fm.RuleRecord{
			{Object: fm.Object{ID: "selected"}, Match: selected, RuleSet: "security", Position: 1, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant},
			{Object: fm.Object{ID: "unselected"}, Match: anyMatch, RuleSet: "security", Position: 2, Action: fm.Deny, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant},
		},
		StaticNATs: []fm.StaticNATRecord{{Object: fm.Object{ID: "published"}, Match: anyMatch, Destination: []fm.Mapping{
			{Original: host("198.51.100.10"), Translated: host("198.51.100.11"), Mode: fm.Offset},
			{Original: host("198.51.100.11"), Translated: host("198.51.100.10"), Mode: fm.Offset},
		}}},
	}
	source, err := fm.Seal(d)
	if err != nil || !source.Complete() {
		t.Fatal(source, err)
	}
	d.Rules, d.StaticNATs = nil, nil
	target, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := MigrationContext{Chain: fm.PolicyChain{RuleSet: "security"}, FromZone: "inside", ToZone: "outside"}
	input := MigrationInput{From: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), Rules: []fm.ID{"selected"}, StaticNATs: []fm.ID{"published"},
		Contexts: []MigrationContextMapping{{Source: coordinate, Target: coordinate}}, Interfaces: []MigrationInterfaceMapping{{Source: "egress", Target: "egress"}}, VRFs: []MigrationVRFMapping{{Source: "", Target: ""}}}
	visits := visitBudget(policy.Limits{}.WithDefaults().MaxVisits)
	domains, err := (Planner{}).migrationNATDomains(t.Context(), source, target, input, &visits)
	if err != nil || len(domains) != 1 {
		t.Fatal("mixed native ownership did not yield one selected wire domain", domains, err)
	}
	for _, domain := range domains {
		for _, box := range domain.source.Traffic.Regions() {
			if box.Destination != host("198.51.100.10") {
				t.Fatal("unselected swapped destination acquired authorization", box)
			}
		}
		if same, err := domain.source.Traffic.Equal(domain.target.Traffic, 4096); err != nil || !same {
			t.Fatal("target request did not retain selected wire ownership", err)
		}
	}
}
