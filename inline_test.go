package firemon_test

import (
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

func TestInlineValuesRetainOwnershipThroughGroupsAndNAT(t *testing.T) {
	base := fm.Data{Metadata: fm.Metadata{Device: "synthetic", Vendor: "huawei"}}
	literal := fm.AddressRecord{Object: fm.Object{ID: "inline", Inline: true}, Ranges: []flow.Range{rng("192.0.2.1", "192.0.2.1")}}
	with := base.Clone()
	with.Addresses = []fm.AddressRecord{literal}
	digest := func(d fm.Data) string {
		t.Helper()
		f, e := fm.Seal(d)
		if e != nil {
			t.Fatal(e)
		}
		return f.SemanticDigest()
	}
	if digest(base) != digest(with) {
		t.Fatal("orphan inline value changed native semantics")
	}
	if len(with.Addresses) != 1 {
		t.Fatal("digest mutated caller graph")
	}
	named := with.Clone()
	named.Addresses[0].Inline = false
	if digest(base) == digest(named) {
		t.Fatal("named declaration ignored")
	}
	unresolved := with.Clone()
	unresolved.Addresses[0].Unsupported = []string{"unknown"}
	if digest(base) == digest(unresolved) {
		t.Fatal("unknown inline evidence ignored")
	}
	for _, owner := range []string{"group", "rule", "static", "dynamic"} {
		t.Run(owner, func(t *testing.T) {
			d := with.Clone()
			ref := fm.AddressRef{Kind: fm.AddressObject, ID: literal.ID}
			m := fm.Match{Sources: []fm.AddressRef{ref}, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
			switch owner {
			case "group":
				d.AddressGroups = []fm.AddressGroupRecord{{Object: fm.Object{ID: "group"}, Members: []fm.AddressRef{ref}}}
			case "rule":
				d.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "rule"}, Match: m, Action: fm.Permit}}
			case "static":
				d.StaticNATs = []fm.StaticNATRecord{{Object: fm.Object{ID: "nat"}, Match: m}}
			case "dynamic":
				d.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "nat"}, Match: m, SourceMode: fm.NoTranslation, DestinationMode: fm.NoTranslation}}
			}
			changed := d.Clone()
			changed.Addresses[0].Ranges[0] = rng("192.0.2.2", "192.0.2.2")
			if digest(d) == digest(changed) {
				t.Fatal("referenced inline mutation ignored")
			}
		})
	}
}
