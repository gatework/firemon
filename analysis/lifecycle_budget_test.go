package analysis_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
)

func TestLifecyclePlansBudgetUnusedCatalogBeforeCopying(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}}).Export()
	for i := range 1000 {
		d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("unused-%d", i))}, Ranges: []flow.AddressRange{d.Addresses[0].Ranges[0]}})
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, reclaim := range []bool{false, true} {
		for _, limit := range []int{32, 100000} {
			planner := plan.Planner{Renderer: hillstone.Renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: limit}}}
			var start, end runtime.MemStats
			runtime.ReadMemStats(&start)
			var result *plan.Plan
			if reclaim {
				result, err = (analysis.Reclaimer{Planner: planner}).Plan(context.Background(), fw, analysis.ReclamationRequest{}, []fm.ID{"2"})
			} else {
				result, err = (analysis.Converger{Planner: planner}).Plan(context.Background(), fw, []fm.ID{"1", "2"}, time.Time{})
			}
			runtime.ReadMemStats(&end)
			if limit == 32 {
				if result != nil || !errors.Is(err, policy.ErrBudget) {
					t.Errorf("catalog escaped lifecycle budget (reclaim=%v): plan=%v err=%v", reclaim, result != nil, err)
				}
				if allocated := end.TotalAlloc - start.TotalAlloc; allocated > 256<<10 {
					t.Errorf("over-budget catalog was copied (reclaim=%v): %d bytes", reclaim, allocated)
				}
			} else if err != nil || result == nil {
				t.Fatalf("adequate budget (reclaim=%v): %v", reclaim, err)
			} else if _, err := result.Verify(context.Background(), result.After()); err != nil {
				t.Fatal(err)
			}
		}
	}
}
