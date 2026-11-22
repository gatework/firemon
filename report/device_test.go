package report

import (
	"slices"
	"testing"

	"github.com/gatework/firemon/inventory"
	"github.com/gatework/firemon/query"
)

// A rule deciding several flows on one firewall is listed once with every
// flow; permits, denies and the default action go to their sections; the
// firewalls follow the order flows cross them.
func TestDeviceViews_GroupByFirewall(t *testing.T) {
	t.Parallel()
	hop := func(cluster string, ds ...HopDecision) Hop { return Hop{Cluster: cluster, Decisions: ds} }
	permit := HopDecision{Outcome: query.OutcomePermit, Rule: "4", Name: "out", Position: 9}
	deny := HopDecision{Outcome: query.OutcomeDeny, Rule: "12", Position: 3}
	deflt := HopDecision{Outcome: query.OutcomeDefault}
	r := Report{
		Firewalls: []Firewall{
			{Cluster: "a", Devices: []inventory.Device{{Name: "a1", Host: "192.0.2.1"}, {Name: "a2"}}},
			{Cluster: "b"},
		},
		Flows: []Flow{
			{Hops: []Hop{hop("b", deny), hop("a", permit)}},
			{Hops: []Hop{hop("a", permit)}},
			{Hops: []Hop{hop("b", deflt)}},
		},
	}
	got := deviceViews(r)
	if len(got) != 2 || got[0].Cluster != "b" || got[1].Cluster != "a" {
		t.Fatalf("order %+v", got)
	}
	a, b := got[1], got[0]
	if len(a.Allowed) != 1 || !slices.Equal(a.Allowed[0].Flows, []int{1, 2}) || len(a.Peers) != 1 || a.Device.Name != "a1" {
		t.Fatalf("a: %+v", a)
	}
	if len(b.Blocked) != 2 || b.Blocked[0].Rule != "12" || b.Blocked[1].Rule != "" || !slices.Equal(b.Blocked[1].Flows, []int{3}) {
		t.Fatalf("b: %+v", b.Blocked)
	}
}
