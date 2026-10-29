package plan_test

import (
	"context"
	"errors"
	"testing"

	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func TestPlannerBatchUnionHonorsConfiguredRegionLimit(t *testing.T) {
	p := plan.Planner{Renderer: renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxRegions: 1}}}
	result, err := p.Plan(context.Background(), baseline(t), []policy.Request{request(t, "192.0.2.1/32"), request(t, "192.0.2.1/32")})
	if result != nil || !errors.Is(err, flow.ErrBudget) {
		t.Fatalf("batch union used fixed region limit: %v, %v", result, err)
	}
}
