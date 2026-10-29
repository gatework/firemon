package policy_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func traffic(t *testing.T, src, dst string) flow.Traffic {
	t.Helper()
	s, _ := flow.PrefixRange(netip.MustParsePrefix(src))
	d, _ := flow.PrefixRange(netip.MustParsePrefix(dst))
	x, err := flow.NewTraffic(64, flow.Box{Source: s, Destination: d, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 0, High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	return x
}
func anyMatch() fm.Match {
	return fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}
}

func TestGlobalUnknownDoesNotRetainCertainDenyOrUnmatched(t *testing.T) {
	for _, rules := range [][]fm.RuleRecord{nil, {{Object: fm.Object{ID: "deny"}, Action: fm.Deny, Match: anyMatch(), RuleSet: "security"}}} {
		d := fm.Data{Metadata: fm.Metadata{Device: "test", Vendor: "hillstone"}, Rules: rules, Diagnostics: []fm.Diagnostic{{Code: "unparsed", Message: "unknown top-level policy"}}}
		fw, err := fm.Seal(d)
		if err != nil {
			t.Fatal(err)
		}
		q := traffic(t, "192.0.2.1/32", "198.51.100.1/32")
		r, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: q})
		if err != nil || r.Complete || !r.Denied.Empty() || !r.Unmatched.Empty() || len(r.Trace) != 0 {
			t.Fatal("uncertain source retained a certain classification", r, err)
		}
	}
}
func base(t *testing.T, rules []fm.RuleRecord) *fm.Firewall {
	t.Helper()
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return fw
}
func TestFirstMatchDenyAndUnknownConsumeBeforeLaterPermit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		action  fm.Action
		unknown bool
	}{{"deny", fm.Deny, false}, {"unknown-condition", fm.Permit, true}} {
		t.Run(tc.name, func(t *testing.T) {
			m := anyMatch()
			if tc.unknown {
				m.Unsupported = []string{"application constraint"}
			}
			fw := base(t, []fm.RuleRecord{{Object: fm.Object{ID: "first"}, Match: m, Action: tc.action, Position: 0, RuleSet: "security"}, {Object: fm.Object{ID: "later"}, Match: anyMatch(), Action: fm.Permit, Position: 1, RuleSet: "security"}})
			res, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.0/24", "198.51.100.1/32"), At: time.Now()})
			if err != nil {
				t.Fatal(err)
			}
			if !res.Allowed.Empty() || len(res.Trace) != 1 || res.Trace[0].Rule != "first" {
				t.Fatal("first match bypassed", res)
			}
			if tc.unknown && res.Unknown.Empty() {
				t.Fatal("unknown treated as certain")
			}
		})
	}
}
func TestTwoHalfSubnetsCoverWholeRequestWithoutSingleRuleContainment(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}}
	for i, cidr := range []string{"192.0.2.0/25", "192.0.2.128/25"} {
		r, _ := flow.PrefixRange(netip.MustParsePrefix(cidr))
		id := fm.ID(cidr)
		d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id}, Ranges: []flow.Range{r}})
		m := anyMatch()
		m.AnySource = false
		m.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: id}}
		d.Rules = append(d.Rules, fm.RuleRecord{Object: fm.Object{ID: id}, Position: i, RuleSet: "security", Match: m, Action: fm.Permit})
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := traffic(t, "192.0.2.0/24", "198.51.100.1/32")
	res, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: q})
	if err != nil {
		t.Fatal(err)
	}
	contains, err := res.Allowed.Contains(q, 64)
	if err != nil || !contains || !res.Unmatched.Empty() || !res.Complete {
		t.Fatal(res, err)
	}
}
func TestRuleVisitBudgetReturnsErrorNotPartialCoverage(t *testing.T) {
	fw := base(t, []fm.RuleRecord{{Object: fm.Object{ID: "1"}, Match: anyMatch(), Action: fm.Permit, RuleSet: "other"}, {Object: fm.Object{ID: "2"}, Match: anyMatch(), Action: fm.Permit, RuleSet: "security"}})
	_, err := (policy.Engine{Limits: policy.Limits{MaxVisits: 1}}).Query(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")})
	if err == nil {
		t.Fatal("budget ignored")
	}
}

func TestSharedGroupDAGIsResolvedOnceAndTraversalBudgetAppliesBeforeExpansion(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, Services: []fm.ServiceRecord{{Object: fm.Object{ID: "leaf"}, Terms: []fm.ServiceTerm{{Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 0, High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}}}}}}
	ref := fm.ServiceRef{Kind: fm.ServiceObject, ID: "leaf"}
	for i := 0; i < 12; i++ {
		id := fm.ID(fmt.Sprintf("group-%d", i))
		d.ServiceGroups = append(d.ServiceGroups, fm.ServiceGroupRecord{Object: fm.Object{ID: id}, Members: []fm.ServiceRef{ref, ref}})
		ref = fm.ServiceRef{Kind: fm.ServiceGroupObject, ID: id}
	}
	m := anyMatch()
	m.AnyService = false
	m.Services = []fm.ServiceRef{ref}
	d.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "permit"}, Match: m, Action: fm.Permit, RuleSet: "security"}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	terms, known, err := (policy.Engine{}).ResolveServices(context.Background(), fw, []fm.ServiceRef{ref}, false)
	if err != nil || !known || len(terms) != 1 {
		t.Fatalf("DAG expanded %d terms, known %v", len(terms), known)
	}
	_, err = (policy.Engine{Limits: policy.Limits{MaxCombinations: 2}}).Query(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")})
	if !errors.Is(err, policy.ErrBudget) {
		t.Fatal("unbounded pre-expansion", err)
	}
}
func TestMissingZoneCannotBecomeCertainPermit(t *testing.T) {
	m := anyMatch()
	m.AnyFromZone = false
	m.FromZones = []fm.ID{"missing"}
	fw := base(t, []fm.RuleRecord{{Object: fm.Object{ID: "permit"}, Match: m, Action: fm.Permit, RuleSet: "security"}})
	result, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32"), FromZone: "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || !result.Allowed.Empty() {
		t.Fatal("dangling zone considered known", result)
	}
}
