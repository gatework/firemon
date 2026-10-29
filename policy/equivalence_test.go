package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

func TestEquivalenceChecksFutureScheduleBoundariesAndLogging(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, Schedules: []fm.ScheduleRecord{{Object: fm.Object{ID: "future"}, Windows: []fm.TimeWindow{{Start: at.Add(time.Hour), End: at.Add(2 * time.Hour)}}}}, Rules: []fm.RuleRecord{{Object: fm.Object{ID: "a"}, RuleSet: "security", Match: anyMatch(), Action: fm.Permit, Log: fm.Known}}}
	d.Rules[0].Match.Schedule = "future"
	a, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	removed := d.Clone()
	removed.Rules = nil
	b, err := fm.Seal(removed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (policy.Engine{}).Equivalent(context.Background(), a, b, at); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("future permit was ignored", err)
	}
	if _, err := (policy.Engine{}).Equivalent(context.Background(), a, b, at.Add(3*time.Hour)); err != nil {
		t.Fatal("expired rule should have no future effect", err)
	}
	d.Rules[0].Log = fm.Irrelevant
	b, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (policy.Engine{}).Equivalent(context.Background(), a, b, at); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("logging change was ignored", err)
	}
}

func TestEquivalenceChecksEveryNativeZonePairAndNATCatalog(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "a"}}, {Object: fm.Object{ID: "b"}}, {Object: fm.Object{ID: "c"}}}, Rules: []fm.RuleRecord{{Object: fm.Object{ID: "permit"}, RuleSet: "security", Match: anyMatch(), Action: fm.Permit, Log: fm.Irrelevant}}}
	d.Rules[0].Match.AnyFromZone = false
	d.Rules[0].Match.FromZones = []fm.ID{"a"}
	a, _ := fm.Seal(d)
	d.Rules[0].Match.AnyToZone = false
	d.Rules[0].Match.ToZones = []fm.ID{"b"}
	b, _ := fm.Seal(d)
	if _, err := (policy.Engine{}).Equivalent(context.Background(), a, b, time.Time{}); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("other egress contexts were ignored", err)
	}
	d = a.Export()
	d.StaticNATs = []fm.StaticNATRecord{{Object: fm.Object{ID: "nat"}, Match: anyMatch()}}
	b, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (policy.Engine{}).Equivalent(context.Background(), a, b, time.Time{}); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("NAT catalog changed under policy equivalence", err)
	}
	if _, err := (policy.Engine{Limits: policy.Limits{MaxCombinations: 2}}).Equivalent(context.Background(), a, a, time.Time{}); !errors.Is(err, policy.ErrBudget) {
		t.Fatal("context budget ignored", err)
	}
}
