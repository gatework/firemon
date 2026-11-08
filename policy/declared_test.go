package policy_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestDeclaredRetainsDisabledInactiveAndShadowedRules(t *testing.T) {
	q := migrationRequest(t).Request
	d := migrationData("paloalto")
	d.StaticNATs = nil
	first := d.Rules[0]
	first.ID, first.Action = "deny", fm.Deny
	d.Rules = []fm.RuleRecord{first}
	d.Schedules = []fm.ScheduleRecord{
		{Object: fm.Object{ID: "expired"}, Windows: []fm.TimeWindow{{Start: q.At.Add(-2 * time.Hour), End: q.At.Add(-time.Hour)}}},
		{Object: fm.Object{ID: "future"}, Windows: []fm.TimeWindow{{Start: q.At.Add(time.Hour), End: q.At.Add(2 * time.Hour)}}},
	}
	for i, id := range []fm.ID{"disabled", "expired", "future"} {
		r := first
		r.ID, r.Action, r.Position = id, fm.Permit, i+1
		r.Disabled = id == "disabled"
		if !r.Disabled {
			r.Match.Schedule = id
		}
		d.Rules = append(d.Rules, r)
	}
	fw := migrationGraph(t, d)
	declared, err := (policy.Engine{}).Declared(t.Context(), fw, q, nil)
	if err != nil || len(declared) != 4 {
		t.Fatal("declaration disappeared through activation or ordered consumption", declared, err)
	}
	for _, match := range declared {
		if !match.Known {
			t.Fatal("established geometry became unknown", match)
		}
		assertPreimage(t, match.Traffic, q.Traffic, nil)
	}
	result, err := (policy.Engine{}).Query(t.Context(), fw, q)
	if err != nil || len(result.Decisions) != 1 || result.Decisions[0].Rule != "deny" {
		t.Fatal("declarations changed effective first-match behavior", result, err)
	}
}

func TestDeclaredPreservesFortinetVIPClassAndCoordinates(t *testing.T) {
	d := preimageData("fortinet")
	d.StaticNATs[0].Order.Section = "vip"
	d.Addresses[0].Ranges = []flow.AddressRange{rangeOf("198.51.100.10/31")}
	d.Addresses[0].VIP = fm.NATRef{Kind: fm.StaticNATObject, ID: "published"}
	d.Rules[1].ID, d.Rules[1].Action = "ordinary-permit", fm.Permit
	disabled := d.Rules[0]
	disabled.ID, disabled.Position, disabled.Disabled = "disabled-vip", 3, true
	d.Rules = append(d.Rules, disabled)
	fw := migrationGraph(t, d)
	q := migrationRequest(t)
	q.Traffic = preimageTraffic(t, preimagePacket("192.0.2.1", "198.51.100.10", 443))
	result, err := (policy.Engine{}).QueryPacket(t.Context(), fw, q)
	if err != nil || !result.Complete || len(result.Paths) != 1 {
		t.Fatal(result, err)
	}
	path := result.Paths[0]
	for _, packet := range []*policy.PacketPath{nil, &path} {
		request := q.Request
		if packet != nil {
			request = path.NativeRequests[0]
		}
		declared, err := (policy.Engine{}).Declared(t.Context(), fw, request, packet)
		if err != nil || len(declared) != 2 {
			t.Fatal("VIP declaration eligibility differs from native policy", declared, err)
		}
		for _, match := range declared {
			if match.Rule == "ordinary-permit" || !match.Known {
				t.Fatal("ordinary permit was presented as a known VIP match", match)
			}
			want := q.Traffic
			if packet != nil {
				want = path.Policy.Allowed
			}
			assertPreimage(t, match.Traffic, want, nil)
		}
	}
	wrong := path.NativeRequests[0]
	wrong.RuleSet = "unselected-chain"
	if matches, err := (policy.Engine{}).Declared(t.Context(), fw, wrong, &path); !errors.Is(err, policy.ErrInvalid) || len(matches) != 0 {
		t.Fatal("unselected native chain acquired packet declarations", matches, err)
	}
	d.Services = []fm.ServiceRecord{{Object: fm.Object{ID: "original-only"}, Terms: []fm.ServiceTerm{{Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}}}}
	d.Rules[0].Match.AnyService = false
	d.Rules[0].Match.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: "original-only"}}
	declared, err := (policy.Engine{}).Declared(t.Context(), migrationGraph(t, d), q.Request, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range declared {
		if match.Rule == d.Rules[0].ID && match.Known {
			t.Fatal("unproved translated service view became a certain declaration", match)
		}
	}
}

func TestDeclaredBoundsAggregateMatchingAndInputs(t *testing.T) {
	d := migrationData("paloalto")
	d.StaticNATs = nil
	first := d.Rules[0]
	for i := range 10 {
		r := first
		r.ID, r.Position = fm.ID(fmt.Sprintf("rule-%d", i)), i+1
		d.Rules = append(d.Rules, r)
	}
	fw := migrationGraph(t, d)
	q := migrationRequest(t).Request
	e := policy.Engine{Limits: policy.Limits{MaxCombinations: 5}}
	if _, _, err := e.Match(t.Context(), fw, first.Match, q, q.Traffic); err != nil {
		t.Fatal("one declaration should fit its own matching limit", err)
	}
	if matches, err := e.Declared(t.Context(), fw, q, nil); !errors.Is(err, policy.ErrBudget) || len(matches) != 0 {
		t.Fatal("per-rule budget resets hid aggregate matching work", matches, err)
	}
	if matches, err := (policy.Engine{Limits: policy.Limits{MaxRegions: 1}}).Declared(t.Context(), fw, q, nil); !errors.Is(err, policy.ErrBudget) || len(matches) != 0 {
		t.Fatal("retained declaration output escaped region bound", matches, err)
	}
	path := policy.PacketPath{Original: q.Traffic, NativeRequests: make([]policy.Request, 6)}
	if matches, err := e.Declared(t.Context(), fw, q, &path); !errors.Is(err, policy.ErrBudget) || len(matches) != 0 {
		t.Fatal("packet chain inputs escaped their bound", matches, err)
	}
	d.Rules[0].Spans = make([]fm.Span, 1000)
	if matches, err := (policy.Engine{Limits: policy.Limits{MaxVisits: 50}}).Declared(t.Context(), migrationGraph(t, d), q, nil); !errors.Is(err, policy.ErrBudget) || len(matches) != 0 {
		t.Fatal("nested declaration copy happened before preflight", matches, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if matches, err := (policy.Engine{}).Declared(ctx, fw, q, nil); !errors.Is(err, context.Canceled) || len(matches) != 0 {
		t.Fatal("canceled declarations returned partial matches", matches, err)
	}
}
