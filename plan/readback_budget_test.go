package plan_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

type countingRenderer struct{ calls int }

func (r *countingRenderer) Render(context.Context, *fm.Firewall, *fm.Firewall, []plan.Change) ([]string, error) {
	r.calls++
	return []string{"verified change"}, nil
}

func readbackGraph(t *testing.T, interfaces int, allow bool) *fm.Firewall {
	t.Helper()
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}}
	for i := range interfaces {
		d.Interfaces = append(d.Interfaces, fm.InterfaceRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("unused-%d", i))}})
	}
	if allow {
		d.Rules = []fm.RuleRecord{{Object: fm.Object{ID: "1"}, RuleSet: "security", Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}}}
	}
	fw, err := fm.Seal(d)
	if err != nil || !fw.Complete() {
		t.Fatalf("fixture: %v", err)
	}
	return fw
}

func TestPlanEntriesPreflightReadbackCapacity(t *testing.T) {
	ctx := context.Background()
	q := request(t, "192.0.2.1/32")
	for _, entry := range []string{"create", "transfer", "preserve", "reuse"} {
		t.Run(entry, func(t *testing.T) {
			before := readbackGraph(t, 100, entry == "reuse")
			for _, limit := range []int{250, 100000} {
				renderer := &countingRenderer{}
				planner := plan.Planner{Renderer: renderer, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: limit}}}
				var result *plan.Plan
				var err error
				switch entry {
				case "create", "reuse":
					result, err = planner.Plan(ctx, before, []policy.Request{q})
				case "transfer":
					result, err = planner.Transfer(ctx, before, []plan.RuleIntent{{Request: q, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}}, time.Time{})
				case "preserve":
					result, err = planner.Preserve(ctx, before, before, nil, time.Time{})
				}
				if limit == 250 {
					if result != nil || !errors.Is(err, policy.ErrBudget) || renderer.calls != 0 {
						t.Fatalf("unreadable plan: result=%v render calls=%d err=%v", result != nil, renderer.calls, err)
					}
				} else if err != nil || result == nil {
					t.Fatalf("adequate readback capacity: %v", err)
				} else {
					if err := result.VerifyBaseline(ctx, before); err != nil {
						t.Fatal(err)
					}
					if _, err := result.Verify(ctx, result.After()); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestReadbackBudgetsObservedGraphBeforeCopying(t *testing.T) {
	ctx := context.Background()
	before := readbackGraph(t, 0, true)
	planner := plan.Planner{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 32}}}
	result, err := planner.Plan(ctx, before, []policy.Request{request(t, "192.0.2.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	observed := readbackGraph(t, 1000, true)
	for _, baseline := range []bool{false, true} {
		var start, end runtime.MemStats
		runtime.ReadMemStats(&start)
		if baseline {
			err = result.VerifyBaseline(ctx, observed)
		} else {
			_, err = result.Verify(ctx, observed)
		}
		runtime.ReadMemStats(&end)
		if !errors.Is(err, policy.ErrBudget) {
			t.Errorf("observed catalog escaped budget (baseline=%v): %v", baseline, err)
		}
		if allocated := end.TotalAlloc - start.TotalAlloc; allocated > 64<<10 {
			t.Errorf("observed catalog copied (baseline=%v): %d bytes", baseline, allocated)
		}
	}
}
