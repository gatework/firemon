package plan_test

import (
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
)

func TestNativeChangesRespectRuleIdentity(t *testing.T) {
	rule := func(id fm.ID, name string, from, to fm.ID) fm.RuleRecord {
		return fm.RuleRecord{
			Object: fm.Object{ID: id, Name: name}, RuleSet: "security",
			Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant,
			Match: fm.Match{
				AnySource: true, AnyDestination: true, AnyService: true,
				FromZones: []fm.ID{from}, ToZones: []fm.ID{to},
			},
		}
	}
	for _, tc := range []struct {
		name, vendor string
		first, next  fm.RuleRecord
		wantErr      bool
	}{
		{
			name: "srx different destination zones", vendor: "srx",
			first: rule("policy:inside/outside/web", "web", "inside", "outside"),
			next:  rule("policy:inside/dmz/web", "web", "inside", "dmz"),
		},
		{
			name: "srx different source zones", vendor: "srx",
			first: rule("policy:inside/outside/web", "web", "inside", "outside"),
			next:  rule("policy:dmz/outside/web", "web", "dmz", "outside"),
		},
		{
			name: "srx duplicate policy name", vendor: "srx",
			first: rule("policy:inside/outside/web", "web", "inside", "outside"),
			next:  rule("different-graph-id", "web", "inside", "outside"), wantErr: true,
		},
		{
			name: "paloalto names span zone pairs", vendor: "paloalto",
			first: rule("web", "web", "inside", "outside"),
			next:  rule("different-graph-id", "web", "inside", "dmz"), wantErr: true,
		},
		{
			name: "huawei names span zone pairs", vendor: "huawei",
			first: rule("web", "web", "inside", "outside"),
			next:  rule("different-graph-id", "web", "inside", "dmz"), wantErr: true,
		},
		{
			name: "hillstone distinct policy ids", vendor: "hillstone",
			first: rule("10", "web", "inside", "outside"),
			next:  rule("20", "web", "inside", "outside"),
		},
		{
			name: "fortinet distinct policy ids", vendor: "fortinet",
			first: rule("10", "web", "inside", "outside"),
			next:  rule("20", "web", "inside", "outside"),
		},
		{
			name: "netscreen distinct policy ids", vendor: "netscreen",
			first: rule("10", "web", "inside", "outside"),
			next:  rule("20", "web", "inside", "outside"),
		},
		{
			name: "asa distinct acl entries", vendor: "asa",
			first: rule("acl:one", "IN", "inside", "outside"),
			next:  rule("acl:two", "IN", "inside", "outside"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.vendor == "asa" {
				tc.first.RuleSet, tc.next.RuleSet = "IN", "IN"
			}
			for _, count := range []int{0, 1} {
				name := "new batch"
				if count == 1 {
					name = "existing rule"
				}
				t.Run(name, func(t *testing.T) {
					tc.next.Position = 1
					rules := []fm.RuleRecord{tc.first, tc.next}
					data := fm.Data{
						Metadata: fm.Metadata{Device: "synthetic", Vendor: tc.vendor},
						Zones: []fm.ZoneRecord{
							{Object: fm.Object{ID: "inside", Name: "inside"}},
							{Object: fm.Object{ID: "outside", Name: "outside"}},
							{Object: fm.Object{ID: "dmz", Name: "dmz"}},
						},
						Rules: rules[:count],
					}
					if tc.vendor == "fortinet" {
						data.Metadata.Context = "root"
					}
					before, err := fm.Seal(data)
					if err != nil || !before.Complete() {
						t.Fatal("invalid baseline", err)
					}
					data.Rules = rules
					after, err := fm.Seal(data)
					if err != nil || !after.Complete() {
						t.Fatal("invalid candidate", err)
					}
					changes := plan.NativeChanges{Additions: plan.NativeAdditions{Rules: rules[count:]}}
					for _, r := range changes.Additions.Rules {
						changes.Rules = append(changes.Rules, plan.Change{Kind: plan.CreateRule, Rule: r.ID})
					}
					err = plan.ValidateNativeChanges(t.Context(), before, after, changes)
					if tc.wantErr {
						if !errors.Is(err, plan.ErrInvalid) {
							t.Fatalf("duplicate policy name accepted: %v", err)
						}
					} else if err != nil {
						t.Fatalf("distinct policies rejected: %v", err)
					}
				})
			}
		})
	}
}
