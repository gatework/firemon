package policy_test

import (
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestNATContextsRejectUnserializableTimes(t *testing.T) {
	at := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		from time.Time
	}{
		{"requested-year", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"requested-offset", at.In(time.FixedZone("invalid", 24*60*60))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "paloalto"}, Zones: []fm.ZoneRecord{{Object: fm.Object{ID: "a"}}, {Object: fm.Object{ID: "b"}}}}
			fw, err := fm.Seal(data)
			if err != nil || !fw.Complete() {
				t.Fatalf("fixture is not a complete graph: %v", err)
			}
			contexts, err := (policy.Engine{}).NATContexts(t.Context(), tc.from, fw)
			if contexts != nil || !errors.Is(err, policy.ErrInvalid) {
				t.Fatalf("invalid time produced %d contexts: %v", len(contexts), err)
			}
		})
	}
}

func TestNATContextsPreserveInstantsAndDistinctNativeChains(t *testing.T) {
	at := time.Date(2026, 11, 7, 9, 30, 0, 0, time.FixedZone("valid", 9*60*60+30*60))
	end := at.Add(time.Hour).UTC()
	fw, err := fm.Seal(fm.Data{
		Metadata:   fm.Metadata{Device: "fw", Vendor: "paloalto"},
		Zones:      []fm.ZoneRecord{{Object: fm.Object{ID: "a"}}, {Object: fm.Object{ID: "b"}}},
		Interfaces: []fm.InterfaceRecord{{Object: fm.Object{ID: "eth"}}},
		Rules: []fm.RuleRecord{
			{Object: fm.Object{ID: "implicit"}, RuleSet: "", Match: anyMatch(), Action: fm.Permit},
			{Object: fm.Object{ID: "explicit"}, RuleSet: "security", Match: anyMatch(), Action: fm.Permit},
		},
		Schedules: []fm.ScheduleRecord{{Object: fm.Object{ID: "active"}, Windows: []fm.TimeWindow{{Start: at, End: end}}}},
	})
	if err != nil || !fw.Complete() {
		t.Fatalf("fixture is not a complete graph: %v", err)
	}
	contexts, err := (policy.Engine{}).NATContexts(t.Context(), at, fw)
	if err != nil || len(contexts) != 32 {
		t.Fatalf("native context identities changed: %d, %v", len(contexts), err)
	}
	index := 0
	for _, ruleSet := range []string{"", "security"} {
		for _, from := range []fm.ID{"a", "b"} {
			for _, to := range []fm.ID{"a", "b"} {
				for _, iface := range []fm.ID{"", "eth"} {
					for _, when := range []time.Time{at.UTC(), end} {
						q := contexts[index]
						if q.RuleSet != ruleSet || q.FromZone != from || q.ToZone != to || q.EgressInterface != iface || !q.At.Equal(when) {
							t.Fatalf("native context missing at %d: %+v", index, q)
						}
						index++
					}
				}
			}
		}
	}
}

func TestNATEffectProofRejectsUnserializableIntentTimes(t *testing.T) {
	base, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	data := base.Export()
	data.StaticNATs = []fm.StaticNATRecord{{Object: fm.Object{ID: "fixed"}, Match: anyMatch(), Source: []fm.Mapping{{Original: rangeOf("192.0.2.1/32"), Translated: rangeOf("203.0.113.1/32"), Mode: fm.Offset}}}}
	after, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	all, err := flow.AllTraffic(4096)
	if err != nil {
		t.Fatal(err)
	}
	region := all.Regions()[0]
	region.Source = rangeOf("192.0.2.1/32")
	domain, err := flow.NewTraffic(4096, region)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	bad := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		at      time.Time
		window  *fm.TimeWindow
		invalid bool
	}{
		{"zero", time.Time{}, nil, false},
		{"valid-offset", at.In(time.FixedZone("valid", 9*60*60+30*60)), nil, false},
		{"requested-year", bad, nil, true},
		{"requested-offset", at.In(time.FixedZone("invalid", 24*60*60)), nil, true},
		{"window-start", at, &fm.TimeWindow{Start: bad, End: bad.Add(time.Hour)}, true},
		{"window-end", at, &fm.TimeWindow{Start: at, End: bad}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intent := policy.NATIntent{Request: policy.Request{Traffic: domain, At: tc.at}, Steps: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "fixed"}}, Window: tc.window}
			proof, err := (policy.Engine{}).ProveNATEffects(t.Context(), base, after, []policy.NATIntent{intent})
			if tc.invalid {
				if !errors.Is(err, policy.ErrInvalid) || proof != (policy.NATProof{}) {
					t.Fatalf("invalid time was not rejected: %+v, %v", proof, err)
				}
			} else if err != nil || !proof.IntentSatisfied || !proof.OutsidePreserved {
				t.Fatalf("valid JSON time was rejected: %+v, %v", proof, err)
			}
		})
	}
	// Equivalent instants with different legal offsets remain separate native
	// context identities. The proof's count is part of the approval encoding.
	data = base.Export()
	window := fm.TimeWindow{Start: at, End: at.Add(time.Hour)}
	data.Schedules = []fm.ScheduleRecord{{Object: fm.Object{ID: "active"}, Windows: []fm.TimeWindow{window}}}
	base, err = fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	data.StaticNATs = after.Export().StaticNATs
	data.StaticNATs[0].Match.Schedule = "active"
	after, err = fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	location := time.FixedZone("valid", 9*60*60+30*60)
	window.Start, window.End = window.Start.In(location), window.End.In(location)
	intent := policy.NATIntent{Request: policy.Request{Traffic: domain, At: at}, Steps: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "fixed"}}, Window: &window}
	proof, err := (policy.Engine{}).ProveNATEffects(t.Context(), base, after, []policy.NATIntent{intent})
	if err != nil || proof.Contexts != 6 || !proof.IntentSatisfied || !proof.OutsidePreserved {
		t.Fatalf("legal offset context identities changed: %+v, %v", proof, err)
	}
}
