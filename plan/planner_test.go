package plan_test

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"net/netip"
	"testing"
)

type renderer struct{ rejectAppend, rejectEarlierAppends bool }

func (r renderer) Render(_ context.Context, before, after *fm.Firewall, changes []plan.Change) ([]string, error) {
	if r.rejectAppend && changes[0].Kind == plan.AppendMembers {
		return nil, errors.New("native append unsupported")
	}
	if r.rejectEarlierAppends && changes[0].Kind == plan.AppendMembers && changes[0].Rule != "10" {
		return nil, errors.New("earlier rule cannot be edited")
	}
	return []string{"reviewable native commands"}, nil
}
func addressRange(cidr string) flow.Range {
	r, _ := flow.PrefixRange(netip.MustParsePrefix(cidr))
	return r
}
func request(t *testing.T, source string) policy.Request {
	t.Helper()
	q, err := flow.NewTraffic(32, flow.Box{Source: addressRange(source), Destination: addressRange("198.51.100.1/32"), Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 0, High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	return policy.Request{Traffic: q}
}
func baseline(t *testing.T) *fm.Firewall {
	t.Helper()
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "src"}, Ranges: []flow.Range{addressRange("192.0.2.1/32")}}, {Object: fm.Object{ID: "dst"}, Ranges: []flow.Range{addressRange("198.51.100.1/32")}}}, Services: []fm.ServiceRecord{{Object: fm.Object{ID: "https"}, Terms: []fm.ServiceTerm{{Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 0, High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}}}}}, Rules: []fm.RuleRecord{{Object: fm.Object{ID: "10"}, RuleSet: "security", Action: fm.Permit, Log: fm.Irrelevant, Match: fm.Match{Sources: []fm.AddressRef{{Kind: fm.AddressObject, ID: "src"}}, Destinations: []fm.AddressRef{{Kind: fm.AddressObject, ID: "dst"}}, Services: []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "https"}}, AnyFromZone: true, AnyToZone: true}}}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}
func TestPlannerReusesCoverageAndPrefersSafeAppend(t *testing.T) {
	fw := baseline(t)
	planner := plan.Planner{Renderer: renderer{}}
	reuse, err := planner.Plan(context.Background(), fw, []policy.Request{request(t, "192.0.2.1/32")})
	if err != nil || len(reuse.Changes()) != 0 {
		t.Fatal(reuse, err)
	}
	appendPlan, err := planner.Plan(context.Background(), fw, []policy.Request{request(t, "192.0.2.2/32")})
	if err != nil {
		t.Fatal(err)
	}
	if len(appendPlan.Changes()) != 1 || appendPlan.Changes()[0].Kind != plan.AppendMembers || appendPlan.Cost().NewRules != 0 || !appendPlan.Proof().OutsidePreserved {
		t.Fatal("safe append not chosen", appendPlan.Changes())
	}
}
func TestUnrenderableCandidateFallsBackToProvenNewRule(t *testing.T) {
	result, err := (plan.Planner{Renderer: renderer{rejectAppend: true}}).Plan(context.Background(), baseline(t), []policy.Request{request(t, "192.0.2.2/32")})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes()) != 1 || result.Changes()[0].Kind != plan.CreateRule || !result.Proof().TargetAllowed || !result.Proof().TargetSatisfied {
		t.Fatal(result.Changes())
	}
}

func TestImpossibleAppendDoesNotExhaustPlanCombinationBudget(t *testing.T) {
	// Extending both addresses would also permit the two unrequested cross
	// pairs. There is only one viable combination: a new exact rule.
	q := request(t, "192.0.2.2/32")
	box := q.Traffic.Boxes()[0]
	box.Destination = addressRange("198.51.100.2/32")
	q.Traffic, _ = flow.NewTraffic(32, box)
	p, err := (plan.Planner{Renderer: renderer{}, MaxCandidates: 1}).Plan(context.Background(), baseline(t), []policy.Request{q})
	if err != nil {
		t.Fatal("impossible append consumed the only plan combination", err)
	}
	if p.Cost().NewRules != 1 || !p.Proof().OutsidePreserved {
		t.Fatal("exact new rule required", p.Cost(), p.Proof())
	}
}

func TestAppendKeepsCrossPairsAlreadyShadowedByEarlierRules(t *testing.T) {
	// The later rule may safely grow in both address dimensions: the earlier
	// two rules already own both cross pairs. A declaration-only prefilter
	// would wrongly discard this cheaper, behavior-preserving append.
	d := baseline(t).Export()
	d.Addresses = append(d.Addresses,
		fm.AddressRecord{Object: fm.Object{ID: "src2"}, Ranges: []flow.Range{addressRange("192.0.2.2/32")}},
		fm.AddressRecord{Object: fm.Object{ID: "dst2"}, Ranges: []flow.Range{addressRange("198.51.100.2/32")}})
	original := d.Rules[0]
	original.Position = 2
	a, b := original, original
	a.ID, a.Position = "first-cross", 0
	b.ID, b.Position = "second-cross", 1
	a.Match.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "src2"}}
	b.Match.Destinations = []fm.AddressRef{{Kind: fm.AddressObject, ID: "dst2"}}
	d.Rules = []fm.RuleRecord{a, b, original}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.2/32")
	box := q.Traffic.Boxes()[0]
	box.Destination = addressRange("198.51.100.2/32")
	q.Traffic, _ = flow.NewTraffic(32, box)
	p, err := (plan.Planner{Renderer: renderer{rejectEarlierAppends: true}}).Plan(context.Background(), fw, []policy.Request{q})
	if err != nil {
		t.Fatal(err)
	}
	if p.Cost().NewRules != 0 || len(p.Changes()) != 1 || p.Changes()[0].Rule != "10" || !p.Proof().OutsidePreserved {
		t.Fatal("safe shadowed append lost", p.Cost(), p.Changes())
	}
}
func TestPlannerRejectsUnknownAndDoesNotMutateBaseline(t *testing.T) {
	fw := baseline(t)
	digest := fw.SemanticDigest()
	_, err := (plan.Planner{Renderer: renderer{}}).Plan(context.Background(), fw, []policy.Request{request(t, "192.0.2.2/32")})
	if err != nil {
		t.Fatal(err)
	}
	if fw.SemanticDigest() != digest || len(fw.Rule("10").Record().Match.Sources) != 1 {
		t.Fatal("planning mutated baseline")
	}
	d := fw.Export()
	d.Rules[0].Match.Unsupported = []string{"application constraint"}
	fw, _ = fm.Seal(d)
	if _, err := (plan.Planner{Renderer: renderer{}}).Plan(context.Background(), fw, []policy.Request{request(t, "192.0.2.2/32")}); err == nil {
		t.Fatal("unknown config became deployable")
	}
}
