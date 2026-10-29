package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

func TestContextsChargesDeclarationsAndAbsoluteWindows(t *testing.T) {
	at := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"},
		Zones:     []fm.ZoneRecord{{Object: fm.Object{ID: "a"}}, {Object: fm.Object{ID: "b"}}},
		Rules:     []fm.RuleRecord{{Object: fm.Object{ID: "r"}, RuleSet: "security", Match: anyMatch(), Action: fm.Permit}},
		Schedules: []fm.ScheduleRecord{{Object: fm.Object{ID: "s"}, Windows: []fm.TimeWindow{{Start: at, End: at.Add(time.Hour)}, {Start: at.Add(2 * time.Hour), End: at.Add(3 * time.Hour)}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{5, 6} {
		rows, err := (policy.Engine{Limits: policy.Limits{MaxVisits: limit}}).Contexts(context.Background(), at, fw)
		if limit == 5 {
			if rows != nil || !errors.Is(err, policy.ErrBudget) {
				t.Fatalf("unbounded context collection: %d, %v", len(rows), err)
			}
		} else if err != nil || len(rows) != 16 {
			t.Fatalf("exact context budget: %d, %v", len(rows), err)
		}
	}
}
