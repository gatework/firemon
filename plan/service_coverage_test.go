package plan_test

import (
	"context"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func TestAppendChargesOnlyUncoveredServiceMembers(t *testing.T) {
	for _, group := range []bool{false, true} {
		for _, split := range []bool{false, true} {
			data := baseline(t).Export()
			term := data.Services[0].Terms[0]
			term.DestinationPort = flow.Interval{Low: 1, High: 200}
			data.Services[0].Terms = []fm.ServiceTerm{term}
			if split {
				data.Services[0].Terms[0].DestinationPort.High = 100
				term.DestinationPort.Low = 101
				data.Services[0].Terms = append(data.Services[0].Terms, term)
			}
			if group {
				data.ServiceGroups = []fm.ServiceGroupRecord{{Object: fm.Object{ID: "web-services"}, Members: data.Rules[0].Match.Services}}
				data.Rules[0].Match.Services = []fm.ServiceRef{{Kind: fm.ServiceGroupObject, ID: "web-services"}}
			}
			fw, err := fm.Seal(data)
			if err != nil {
				t.Fatal(err)
			}
			q := request(t, "192.0.2.2/32")
			region := q.Traffic.Regions()[0]
			region.DestinationPort = flow.Interval{Low: 1, High: 200}
			q.Traffic, err = flow.NewTraffic(32, region)
			if err != nil {
				t.Fatal(err)
			}
			// Existing source already has the whole service. Only the new source
			// belongs in the delta; service representation must not affect cost.
			result, err := (plan.Planner{Renderer: renderer{}}).Plan(context.Background(), fw, []policy.Request{q})
			if err != nil {
				t.Fatal(err)
			}
			changes := result.Changes()
			if len(changes) != 1 || changes[0].Kind != plan.AppendMembers || len(changes[0].Sources) != 1 || len(changes[0].Services) != 0 {
				t.Fatalf("covered service appended (group=%v, split=%v): %+v", group, split, changes)
			}
			cost := result.Cost()
			if cost.AppendedMembers != 1 || cost.NewObjects != 1 || len(result.After().Services()) != len(fw.Services()) {
				t.Fatalf("covered service charged: %+v", cost)
			}
		}
	}
}
