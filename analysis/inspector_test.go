package analysis_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
)

func TestInspectorNestedPathsRoleRangesAndFirstMatch(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}}).Export()
	ref := fm.AddressRef{Kind: fm.AddressObject, ID: "192.0.2.1"}
	d.AddressGroups = []fm.AddressGroupRecord{{Object: fm.Object{ID: "inner"}, Members: []fm.AddressRef{ref}}, {Object: fm.Object{ID: "outer"}, Members: []fm.AddressRef{{Kind: fm.AddressGroupObject, ID: "inner"}}}}
	d.Rules[0].Action = fm.Deny
	d.Rules[1].Match.Sources = []fm.AddressRef{{Kind: fm.AddressGroupObject, ID: "outer"}}
	d.Rules[2].Disabled = true
	d.Rules[2].Match.AnySource = true
	d.Rules[2].Match.Sources = nil
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.1", "198.51.100.1")
	r, err := (analysis.Inspector{}).Inspect(context.Background(), fw, analysis.InspectionRequest{Object: ref, Evaluation: &q})
	if err != nil || len(r.Exposures) != 3 || r.Exposures[0].Effective != analysis.True || r.Exposures[1].Declared != analysis.True || r.Exposures[1].Effective != analysis.False || r.Exposures[2].Effective != analysis.False {
		t.Fatal(r, err)
	}
	nested, any := false, false
	for _, rr := range r.References {
		if rr.Rule == "2" && rr.Role == analysis.Source && len(rr.Path) == 3 && rr.Path[0].ID == "outer" && rr.Path[2] == ref {
			nested = true
		}
		if rr.Rule == "3" && rr.Wildcard {
			any = true
		}
	}
	if !nested || !any {
		t.Fatal("lost nested source path or wildcard", r.References)
	}
	d.Addresses[0].Ranges = []flow.AddressRange{{First: netip.MustParseAddr("192.0.2.0"), Last: netip.MustParseAddr("192.0.2.255")}}
	fw, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	addresses, _ := flow.NewAddressSet(flow.AddressRange{First: netip.MustParseAddr("192.0.2.1"), Last: netip.MustParseAddr("192.0.2.1")})
	r, err = (analysis.Inspector{}).Inspect(context.Background(), fw, analysis.InspectionRequest{Addresses: addresses})
	if err != nil || len(r.Objects) == 0 || r.Objects[0].Relation != "contains" || len(r.Exposures) != 0 {
		t.Fatal(r, err)
	}
	for _, rr := range r.References {
		if rr.Wildcard {
			t.Fatal("wildcard inferred without context", rr)
		}
	}
}
func TestInspectorCyclesBudgetsAndDynamicPoolsRemainPossible(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}}).Export()
	ref := fm.AddressRef{Kind: fm.AddressObject, ID: "192.0.2.1"}
	d.AddressGroups = []fm.AddressGroupRecord{{Object: fm.Object{ID: "cycle"}, Members: []fm.AddressRef{{Kind: fm.AddressGroupObject, ID: "cycle"}, ref}}}
	d.NATPools = []fm.NATPoolRecord{{Object: fm.Object{ID: "pool"}, Ranges: d.Addresses[0].Ranges}}
	d.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "dynamic"}, Match: d.Rules[0].Match, SourceMode: fm.DynamicIP, SourcePool: "pool", DestinationMode: fm.NoTranslation}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	set, _ := flow.NewAddressSet(d.Addresses[0].Ranges...)
	r, err := (analysis.Inspector{}).Inspect(context.Background(), fw, analysis.InspectionRequest{Addresses: set})
	if err != nil || r.Complete || len(r.Issues) == 0 || len(r.DynamicPools) != 1 || !r.DynamicPools[0].PossibleAllocation || r.DynamicPools[0].Pool != "pool" {
		t.Fatal(r, err)
	}
	_, err = (analysis.Inspector{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 1}}}).Inspect(context.Background(), fw, analysis.InspectionRequest{Object: ref})
	if !errors.Is(err, policy.ErrBudget) {
		t.Fatal(err)
	}
}
func TestInspectorStaticAliasesUseOrderedForwardValidation(t *testing.T) {
	raw := "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\nset interfaces ge-0/0/1 unit 0 family inet address 203.0.113.1/24\nset security zones security-zone inside interfaces ge-0/0/0.0\nset security zones security-zone outside interfaces ge-0/0/1.0\nset security nat static rule-set public from zone outside\n"
	rule := func(name, public, real string) string {
		return "set security nat static rule-set public rule " + name + " match destination-address " + public + "\nset security nat static rule-set public rule " + name + " then static-nat prefix " + real + "\n"
	}
	raw += "set routing-options static route 10.0.0.0/24 next-hop 192.0.2.254\n" + rule("earlier", "203.0.113.1/32", "10.0.0.1/32") + rule("later", "203.0.113.1/32", "192.0.2.1/32")
	fw, err := (vendors.Parser{}).Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fw", Vendor: "srx"})
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "198.51.100.1", "192.0.2.1")
	q.FromZone = "outside"
	set, _ := flow.NewAddressSet(q.Traffic.Regions()[0].Destination)
	r, err := (analysis.Inspector{}).Inspect(context.Background(), fw, analysis.InspectionRequest{Addresses: set, Aliases: &analysis.AliasInspection{Request: policy.PacketRequest{Request: q}, View: policy.RealView}})
	if err != nil || r.Aliases == nil || len(r.Aliases.Candidates) != 0 || len(r.Aliases.Unmatched) != 1 {
		t.Fatal(r, err)
	}
}

func TestInspectorPreservesProvenAliasAndNoAliasRemainder(t *testing.T) {
	base := "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\nset interfaces ge-0/0/1 unit 0 family inet address 203.0.113.1/24\nset security zones security-zone inside interfaces ge-0/0/0.0\nset security zones security-zone outside interfaces ge-0/0/1.0\n"
	nat := "set security nat static rule-set public from zone outside\nset security nat static rule-set public rule one match destination-address 203.0.113.10/32\nset security nat static rule-set public rule one then static-nat prefix 192.0.2.10/32\n"
	for _, withNAT := range []bool{false, true} {
		raw := base
		if withNAT {
			raw += nat
		}
		fw, err := (vendors.Parser{}).Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fw", Vendor: "srx"})
		if err != nil {
			t.Fatal(err)
		}
		q := request(t, "198.51.100.1", "192.0.2.10")
		q.FromZone = "outside"
		set, _ := flow.NewAddressSet(q.Traffic.Regions()[0].Destination)
		r, err := (analysis.Inspector{}).Inspect(context.Background(), fw, analysis.InspectionRequest{Addresses: set, Aliases: &analysis.AliasInspection{Request: policy.PacketRequest{Request: q}, View: policy.RealView}})
		if err != nil || r.Aliases == nil {
			t.Fatal(r, err)
		}
		if withNAT {
			if len(r.Aliases.Candidates) != 1 || len(r.Aliases.Unmatched) != 0 || r.Aliases.Candidates[0].Wire[0].Destination.First.String() != "203.0.113.10" {
				t.Fatal(r.Aliases)
			}
		} else if len(r.Aliases.Candidates) != 0 || len(r.Aliases.Unmatched) != 1 {
			t.Fatal(r.Aliases)
		}
	}
}

func TestInspectorBoundsCombinedExposureReport(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	q := request(t, "192.0.2.1", "198.51.100.1")
	_, err := (analysis.Inspector{Engine: policy.Engine{Limits: policy.Limits{MaxRegions: 1}}}).Inspect(context.Background(), fw, analysis.InspectionRequest{Object: fm.AddressRef{Kind: fm.AddressObject, ID: "192.0.2.1"}, Evaluation: &q})
	if !errors.Is(err, flow.ErrBudget) {
		t.Fatal("declared and effective traffic exceeded report capacity", err)
	}
}
