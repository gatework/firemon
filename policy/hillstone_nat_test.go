package policy_test

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func bnat() fm.StaticNATRecord {
	return fm.StaticNATRecord{Object: fm.Object{ID: "server"}, Match: anyMatch(), Bidirectional: true,
		Order:  fm.NATOrder{Section: "bnat", Position: 30},
		Source: []fm.Mapping{{Original: rangeOf("192.0.2.0/24"), Translated: rangeOf("203.0.113.0/24"), Mode: fm.Offset}}}
}

func TestHillstoneBNATReverseAndTwoDirectionsPreserveOffsets(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, StaticNATs: []fm.StaticNATRecord{bnat()}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, src, dst, wantSrc, wantDst string }{
		{"reverse", "198.51.100.1/32", "203.0.113.128/25", "198.51.100.1/32", "192.0.2.128/25"},
		{"both", "192.0.2.5/32", "203.0.113.128/25", "203.0.113.5/32", "192.0.2.128/25"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, test.src, test.dst)})
			if err != nil {
				t.Fatal(err)
			}
			if !result.Complete || !result.Unknown.Empty() || !result.Unmatched.Empty() || len(result.Relations) != 1 {
				t.Fatalf("incomplete mapping: %+v", result)
			}
			r := result.Relations[0]
			if !r.Exact || r.PossibleAllocation {
				t.Fatal("fixed mapping lost exactness")
			}
			boxes := r.Translated.Boxes()
			if len(boxes) != 1 || boxes[0].Source != rangeOf(test.wantSrc) || boxes[0].Destination != rangeOf(test.wantDst) {
				t.Fatalf("wrong offset: %+v", boxes)
			}
		})
	}
}

func TestHillstoneBNATPrecedesSNATRegardlessOfConfigPosition(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone", Software: "5.5R8"}, StaticNATs: []fm.StaticNATRecord{bnat()},
		NATPools:    []fm.NATPoolRecord{{Object: fm.Object{ID: "pat"}, Ranges: []flow.Range{rangeOf("198.51.100.1/32")}}},
		DynamicNATs: []fm.DynamicNATRecord{{Object: fm.Object{ID: "fallback"}, Order: fm.NATOrder{Section: "snat", Position: 1}, Match: anyMatch(), SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation, SourcePool: "pat"}}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.9/32")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Relations) != 1 || r.Relations[0].ID != "server" || !r.Relations[0].Exact {
		t.Fatalf("PAT shadowed BNAT: %+v", r)
	}
}

func TestHillstoneNATStagesMatchOriginalDestinationAndComposePerPair(t *testing.T) {
	// This pipeline is pinned to the 5.5R8 documented delayed rewrite model.
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone", Software: "5.5R8"},
		Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "public"}, Ranges: []flow.Range{rangeOf("203.0.113.10/32")}}},
		NATPools:  []fm.NATPoolRecord{{Object: fm.Object{ID: "pat"}, Ranges: []flow.Range{rangeOf("198.51.100.1/32")}}}}
	m := anyMatch()
	m.AnyDestination = false
	m.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "public"}}
	d.DynamicNATs = []fm.DynamicNATRecord{
		{Object: fm.Object{ID: "source"}, Match: m, Order: fm.NATOrder{Stage: 2, Section: "snat", Position: 1}, SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation, SourcePool: "pat"},
		{Object: fm.Object{ID: "destination"}, Match: m, Order: fm.NATOrder{Stage: 1, Section: "dnat", Position: 2}, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP,
			Destination: []fm.Mapping{{Original: rangeOf("203.0.113.10/32"), Translated: rangeOf("10.0.0.10/32"), Mode: fm.Constant}}},
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	one := traffic(t, "192.0.2.1/32", "203.0.113.10/32")
	two := traffic(t, "192.0.2.2/32", "203.0.113.11/32")
	input, _ := one.Union(two, 32)
	r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: input})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Relations) != 1 || r.Relations[0].Exact || !r.Relations[0].PossibleAllocation {
		t.Fatalf("wrong composition: %+v", r)
	}
	boxes := r.Relations[0].Translated.Boxes()
	if len(boxes) != 1 || boxes[0].Source != rangeOf("198.51.100.1/32") || boxes[0].Destination != rangeOf("10.0.0.10/32") {
		t.Fatal(boxes)
	}
	if !sameTraffic(t, r.Unmatched, two) || !sameTraffic(t, r.Relations[0].Original, one) {
		t.Fatal("stage composition expanded request pairs")
	}
}

func TestNATUnknownSourceCannotLeaveCertainRelations(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, StaticNATs: []fm.StaticNATRecord{bnat()}, Diagnostics: []fm.Diagnostic{{Code: "unparsed", Message: "native behavior not decoded"}}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := policy.Request{Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")}
	r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
	if err != nil {
		t.Fatal(err)
	}
	if r.Complete || !sameTraffic(t, r.Unknown, q.Traffic) || len(r.Relations) != 0 || !r.Unmatched.Empty() {
		t.Fatal("unknown global syntax retained certain mappings", r)
	}
}

func TestNATCancelledEmptyChainDoesNotReturnSuccess(t *testing.T) {
	fw, _ := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (policy.Engine{}).QueryNAT(ctx, fw, policy.Request{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func sameTraffic(t *testing.T, a, b flow.Traffic) bool {
	t.Helper()
	left, err := a.Difference(b, 128)
	if err != nil {
		t.Fatal(err)
	}
	right, err := b.Difference(a, 128)
	if err != nil {
		t.Fatal(err)
	}
	return left.Empty() && right.Empty()
}

func TestNATNativePipelineBudgetCoversAllStageVisits(t *testing.T) {
	fw, _ := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, StaticNATs: []fm.StaticNATRecord{bnat()}})
	_, err := (policy.Engine{Limits: policy.Limits{Rules: 1}}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.5/32", "203.0.113.10/32")})
	if !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("stage visits bypassed limit: %v", err)
	}
}

func TestBNATReverseRetainsInvalidSourceEvidence(t *testing.T) {
	r := bnat()
	r.Match.AnySource = false
	r.Match.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "missing"}}
	fw, _ := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, StaticNATs: []fm.StaticNATRecord{r}})
	result, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Traffic: traffic(t, "198.51.100.1/32", "203.0.113.10/32")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.Unknown.Empty() || len(result.Relations) != 0 {
		t.Fatal("inverse erased missing reference evidence")
	}
}

func TestHillstoneEgressPredicateCannotBeTreatedAsOnlyAllocationTarget(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"},
		Interfaces:  []fm.InterfaceRecord{{Object: fm.Object{ID: "wan"}}},
		NATPools:    []fm.NATPoolRecord{{Object: fm.Object{ID: "pool"}, Ranges: []flow.Range{rangeOf("203.0.113.1/32")}}},
		DynamicNATs: []fm.DynamicNATRecord{{Object: fm.Object{ID: "pat"}, Match: anyMatch(), Interface: "wan", SourcePool: "pool", SourceMode: fm.DynamicIPPort, DestinationMode: fm.NoTranslation}}}
	fw, _ := fm.Seal(d)
	q := policy.Request{Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")}
	for _, iface := range []fm.ID{"", "other", "wan"} {
		q.EgressInterface = iface
		r, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
		if err != nil {
			t.Fatal(err)
		}
		switch iface {
		case "":
			if r.Unknown.Empty() || r.Complete {
				t.Fatal("missing egress became certain match")
			}
		case "other":
			if !sameTraffic(t, r.Unmatched, q.Traffic) {
				t.Fatal("wrong egress selected")
			}
		case "wan":
			if !r.Complete || len(r.Relations) != 1 {
				t.Fatal("explicit matching egress rejected")
			}
		}
	}
}
