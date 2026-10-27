package analysis_test

import (
	"context"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/hillstone"
)

func graph(t *testing.T, pairs [][2]string) *fm.Firewall {
	t.Helper()
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}}
	seen := make(map[fm.ID]bool)
	for i, pair := range pairs {
		q := request(t, pair[0], pair[1])
		box := q.Traffic.Boxes()[0]
		for _, r := range []flow.Range{box.Source, box.Destination} {
			id := fm.ID(r.First.String())
			if !seen[id] {
				d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id, Name: string(id)}, Ranges: []flow.Range{r}})
				seen[id] = true
			}
		}
		id := fm.ID(string(rune('1' + i)))
		d.Rules = append(d.Rules, fm.RuleRecord{Object: fm.Object{ID: id}, Position: i, RuleSet: "security", Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnyFromZone: true, AnyToZone: true, AnyService: true, Sources: []fm.AddressRef{{Kind: fm.AddressObject, ID: fm.ID(pair[0])}}, Destinations: []fm.AddressRef{{Kind: fm.AddressObject, ID: fm.ID(pair[1])}}}})
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestConvergenceProvesWholePlanAndKeepsSharedObjects(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}})
	p, err := (analysis.Converger{Planner: plan.Planner{Renderer: hillstone.Renderer{}}}).Plan(context.Background(), fw, []fm.ID{"2", "1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.After().Rules()) != 1 || p.After().Rule("1") == nil || len(p.After().Addresses()) != len(fw.Addresses()) || len(fw.Rules()) != 2 {
		t.Fatal("wrong survivor/shared object ownership")
	}
	if _, err := p.Verify(context.Background(), p.After()); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Preservation(); !ok {
		t.Fatal("missing whole plan proof")
	}
}

func TestConvergenceRejectsCrossPairsAndInterveningDeny(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pairs [][2]string
		deny  bool
		ids   []fm.ID
	}{
		{"cross-pairs", [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.2"}}, false, []fm.ID{"1", "2"}},
		{"deny-between", [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}}, true, []fm.ID{"1", "3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := graph(t, tc.pairs)
			if tc.deny {
				d := fw.Export()
				d.Rules[1].Action = fm.Deny
				var err error
				fw, err = fm.Seal(d)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := (analysis.Converger{Planner: plan.Planner{Renderer: hillstone.Renderer{}}}).Plan(context.Background(), fw, tc.ids); err == nil {
				t.Fatal("unsafe convergence accepted")
			}
		})
	}
}
