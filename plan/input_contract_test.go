package plan_test

import (
	"context"
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func TestPlanningInvalidInputAndCancellation(t *testing.T) {
	p := plan.Planner{}
	var approved *plan.Plan
	for name, call := range map[string]func(context.Context) error{
		"plan":     func(ctx context.Context) error { _, err := p.Plan(ctx, nil, []policy.Request{{}}); return err },
		"preserve": func(ctx context.Context) error { _, err := p.Preserve(ctx, nil, nil, nil, time.Time{}); return err },
		"transfer": func(ctx context.Context) error { _, err := p.Transfer(ctx, nil, nil, time.Time{}); return err },
		"readback": func(ctx context.Context) error { _, err := approved.Verify(ctx, nil); return err },
		"baseline": func(ctx context.Context) error { return approved.VerifyBaseline(ctx, nil) },
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := call(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
			if err := call(context.Background()); !errors.Is(err, plan.ErrInvalid) {
				t.Fatalf("invalid misclassified: %v", err)
			}
		})
	}
}

type nilRenderer struct{}

func (*nilRenderer) Render(context.Context, *fm.Firewall, *fm.Firewall, []plan.Change) ([]string, error) {
	panic("typed-nil renderer invoked")
}
func TestTypedNilRendererCannotAuthorizePlan(t *testing.T) {
	var native *nilRenderer
	fw := baseline(t)
	_, err := (plan.Planner{Renderer: native}).Plan(context.Background(), fw, []policy.Request{request(t, "192.0.2.2/32")})
	if !errors.Is(err, plan.ErrInvalid) {
		t.Fatalf("renderer contract: %v", err)
	}
}
