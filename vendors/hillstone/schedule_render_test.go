package hillstone_test

import (
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/vendors/hillstone"
)

func TestRender_OpenEndedWindowRefused(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := &design.Plan{Kind: design.PlanKindCleanup, Changes: []design.Change{design.AddSchedule{Schedule: firemon.Schedule{
		Name: "open", Windows: []firemon.TimeWindow{{Start: start}},
	}}}}
	s, err := hillstone.Renderer{}.Render(p)
	if err == nil {
		t.Fatalf("a window without an end rendered: %+v", s)
	}
}
