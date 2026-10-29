package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestNATPreservationRejectsScreenOSPolicyOwnershipChange(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "ns", Vendor: "netscreen"},
		Rules:       []fm.RuleRecord{{Object: fm.Object{ID: "10"}, RuleSet: "security", Match: anyMatch(), Action: fm.Permit, Position: 1}},
		NATPools:    []fm.NATPoolRecord{{Object: fm.Object{ID: "dip"}, Ranges: []flow.Range{rangeOf("203.0.113.1/32")}}},
		DynamicNATs: []fm.DynamicNATRecord{{Object: fm.Object{ID: "policy:10"}, Match: anyMatch(), Rule: "10", Order: fm.NATOrder{Section: "policy"}, SourceMode: fm.DynamicIP, DestinationMode: fm.NoTranslation, SourcePool: "dip"}},
	}
	before, err := fm.Seal(d)
	if err != nil || !before.Complete() {
		t.Fatal("invalid baseline", err)
	}
	e := policy.Engine{}
	if err := e.PreserveNAT(context.Background(), before, before, time.Time{}); err != nil {
		t.Fatal("unchanged translation rejected", err)
	}
	r := d.Rules[0]
	r.ID, r.Position = "9", 0
	d.Rules = append(d.Rules, r)
	after, err := fm.Seal(d)
	if err != nil || !after.Complete() {
		t.Fatal("invalid candidate", err)
	}
	if err := e.PreserveNAT(context.Background(), before, after, time.Time{}); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("ordinary permit stole policy NAT ownership", err)
	}
}

func TestNATPreservationIncludesExistingObjectDependencies(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "hs", Vendor: "hillstone"},
		Addresses:  []fm.AddressRecord{{Object: fm.Object{ID: "src"}, Ranges: []flow.Range{rangeOf("192.0.2.1/32")}}},
		StaticNATs: []fm.StaticNATRecord{{Object: fm.Object{ID: "fixed"}, Match: anyMatch(), Source: []fm.Mapping{{Original: rangeOf("192.0.2.0/24"), Translated: rangeOf("203.0.113.0/24"), Mode: fm.Offset}}}},
	}
	d.StaticNATs[0].Match.AnySource = false
	d.StaticNATs[0].Match.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "src"}}
	before, err := fm.Seal(d)
	if err != nil || !before.Complete() {
		t.Fatal(err)
	}
	d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: "new"}, Ranges: []flow.Range{rangeOf("192.0.2.2/32")}})
	added, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := (policy.Engine{}).PreserveNAT(context.Background(), before, added, time.Time{}); err != nil {
		t.Fatal("unreferenced new declaration changed NAT", err)
	}
	d.Addresses[0].Ranges = []flow.Range{rangeOf("192.0.2.3/32")}
	after, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := (policy.Engine{}).PreserveNAT(context.Background(), before, after, time.Time{}); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("unchanged NAT DTO hid changed match dependency", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (policy.Engine{}).PreserveNAT(ctx, before, before, time.Time{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestNATPreservationChecksFuturePolicyOwnership(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := fm.Data{Metadata: fm.Metadata{Device: "ns", Vendor: "netscreen"},
		Schedules:   []fm.ScheduleRecord{{Object: fm.Object{ID: "future"}, Windows: []fm.TimeWindow{{Start: at.Add(time.Hour), End: at.Add(2 * time.Hour)}}}},
		Rules:       []fm.RuleRecord{{Object: fm.Object{ID: "10"}, RuleSet: "security", Match: anyMatch(), Action: fm.Permit, Position: 1}},
		NATPools:    []fm.NATPoolRecord{{Object: fm.Object{ID: "dip"}, Ranges: []flow.Range{rangeOf("203.0.113.1/32")}}},
		DynamicNATs: []fm.DynamicNATRecord{{Object: fm.Object{ID: "policy:10"}, Match: anyMatch(), Rule: "10", Order: fm.NATOrder{Section: "policy"}, SourceMode: fm.DynamicIP, DestinationMode: fm.NoTranslation, SourcePool: "dip"}},
	}
	before, err := fm.Seal(d)
	if err != nil || !before.Complete() {
		t.Fatal("invalid baseline", err)
	}
	r := d.Rules[0]
	r.ID, r.Position, r.Match.Schedule = "9", 0, "future"
	d.Rules = append(d.Rules, r)
	after, err := fm.Seal(d)
	if err != nil || !after.Complete() {
		t.Fatal("invalid candidate", err)
	}
	e := policy.Engine{}
	if err := e.PreserveNAT(context.Background(), before, after, at); !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("future policy stole NAT ownership without invalidating proof", err)
	}
	if err := e.PreserveNAT(context.Background(), before, after, at.Add(3*time.Hour)); err != nil {
		t.Fatal("expired policy cannot change future NAT ownership", err)
	}
}
