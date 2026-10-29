package plan_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func TestCandidateConstructionBudgetsUnreferencedCatalog(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "test", Vendor: "hillstone"}}
	for i := range 100 {
		d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("unused-%d", i))}, Ranges: []flow.Range{addressRange("203.0.113.1/32")}})
	}
	fw, err := fm.Seal(d)
	if err != nil || !fw.Complete() {
		t.Fatalf("fixture: %v", err)
	}
	q := request(t, "192.0.2.1/32")
	for _, transfer := range []bool{false, true} {
		for _, limit := range []int{32, 100000} {
			p := plan.Planner{Renderer: renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: limit}}}
			var result *plan.Plan
			if transfer {
				result, err = p.Transfer(context.Background(), fw, []plan.RuleIntent{{Request: q, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}}, time.Time{})
			} else {
				result, err = p.Plan(context.Background(), fw, []policy.Request{q})
			}
			if limit == 32 {
				if result != nil || !errors.Is(err, policy.ErrBudget) {
					t.Errorf("catalog escaped limit (transfer=%v): plan=%v, err=%v", transfer, result != nil, err)
				}
			} else if err != nil || result == nil {
				t.Fatalf("adequate catalog budget (transfer=%v): %v", transfer, err)
			}
		}
	}
}

func TestTransferRejectsOversizedTrafficBeforeCopying(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "test", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.1/32")
	box := q.Traffic.Boxes()[0]
	boxes := make([]flow.Box, 4096)
	for i := range boxes {
		boxes[i] = box
		boxes[i].DestinationPort = flow.Interval{Low: uint16(i), High: uint16(i)}
	}
	q.Traffic, err = flow.NewTraffic(len(boxes), boxes...)
	if err != nil {
		t.Fatal(err)
	}
	p := plan.Planner{Renderer: renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 1, MaxRegions: 1}}}
	intents := []plan.RuleIntent{{Request: q, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 5 {
		result, err := p.Transfer(context.Background(), fw, intents, time.Time{})
		if result != nil || (!errors.Is(err, policy.ErrBudget) && !errors.Is(err, flow.ErrBudget)) {
			t.Fatalf("oversized input: %v, %v", result, err)
		}
	}
	runtime.ReadMemStats(&after)
	// Rejecting a huge immutable input under a one-region cap must not allocate
	// a copy of that input. This generous bound excludes the input built above.
	if bytes := (after.TotalAlloc - before.TotalAlloc) / 5; bytes > 16<<10 {
		t.Fatalf("budget rejection copied oversized input: %d bytes/call", bytes)
	}
}
