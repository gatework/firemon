package plan_test

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

type candidateRenderer struct {
	rejectCheapest, rejectAppends, rejectAll bool
}

type failedCandidateRenderer struct {
	cause error
	calls int
}

func (r *failedCandidateRenderer) Render(context.Context, *fm.Firewall, *fm.Firewall, []plan.Change) ([]string, error) {
	r.calls++
	return nil, r.cause
}

func TestCandidateRenderingKeepsComputationAndForeignRefusalsFatal(t *testing.T) {
	for _, cause := range []error{
		errors.Join(plan.ErrRender, policy.ErrBudget),
		errors.Join(plan.ErrRender, flow.ErrBudget),
		errors.Join(plan.ErrRender, context.Canceled),
		&plan.RejectionError{Stage: plan.RepresentationRejection, Err: plan.ErrRender},
	} {
		native := &failedCandidateRenderer{cause: cause}
		result, err := (plan.Planner{Renderer: native}).Plan(context.Background(), baseline(t), []policy.Request{request(t, "192.0.2.2/32")})
		if result != nil || !errors.Is(err, cause) || native.calls != 1 {
			t.Errorf("fatal failure retried: calls=%d err=%v", native.calls, err)
		}
	}
}

func (r candidateRenderer) Render(_ context.Context, _, _ *fm.Firewall, changes []plan.Change) ([]string, error) {
	change := changes[0]
	if r.rejectAll || change.Kind == plan.AppendMembers && (r.rejectAppends || r.rejectCheapest && change.Rule == "10") {
		return nil, plan.ErrRender
	}
	return []string{"reviewed command"}, nil
}

func twoAppendCandidates(t *testing.T) *fm.Firewall {
	t.Helper()
	data := baseline(t).Export()
	first, second := data.Rules[0], data.Rules[0]
	first.ID, second.ID = "20", "10"
	// Native positions tie, so ID breaks the cost tie. The cheaper candidate
	// comes last in declaration order and must replace an already full heap.
	data.Rules = []fm.RuleRecord{first, second}
	fw, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestCandidateLimitCountsCostOrderedAttempts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		limit     int
		renderer  candidateRenderer
		wantRule  fm.ID
		wantKind  plan.ChangeKind
		wantError error
	}{
		{"late-cheapest", 1, candidateRenderer{}, "10", plan.AppendMembers, nil},
		{"untried-append", 1, candidateRenderer{rejectCheapest: true}, "", 0, policy.ErrBudget},
		{"second-append", 2, candidateRenderer{rejectCheapest: true}, "20", plan.AppendMembers, nil},
		{"untried-create", 2, candidateRenderer{rejectAppends: true}, "", 0, policy.ErrBudget},
		{"create-after-appends", 3, candidateRenderer{rejectAppends: true}, "", plan.CreateRule, nil},
		{"exact-search-exhaustion", 3, candidateRenderer{rejectAll: true}, "", 0, plan.ErrUnsafe},
		{"complete-search-exhaustion", 4, candidateRenderer{rejectAll: true}, "", 0, plan.ErrUnsafe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := (plan.Planner{Renderer: tc.renderer, MaxCandidates: tc.limit}).Plan(
				context.Background(), twoAppendCandidates(t), []policy.Request{request(t, "192.0.2.2/32")},
			)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("plan error %v, want %v", err, tc.wantError)
			}
			if tc.wantError != nil {
				if result != nil {
					t.Fatal("partial plan escaped failed search")
				}
				return
			}
			changes := result.Changes()
			if len(changes) != 1 || changes[0].Kind != tc.wantKind || tc.wantRule != "" && changes[0].Rule != tc.wantRule {
				t.Fatalf("wrong ranked alternative: %+v", changes)
			}
			if !result.Proof().TargetSatisfied || !result.Proof().OutsidePreserved {
				t.Fatal("unproven ranked alternative")
			}
		})
	}
}

func TestOneAttemptCanReturnSafeAppend(t *testing.T) {
	result, err := (plan.Planner{Renderer: renderer{}, MaxCandidates: 1}).Plan(
		context.Background(), baseline(t), []policy.Request{request(t, "192.0.2.2/32")},
	)
	if err != nil {
		t.Fatal("unused create alternative exhausted safe append budget:", err)
	}
	if result.Cost().NewRules != 0 || result.Changes()[0].Kind != plan.AppendMembers {
		t.Fatal("safe append lost")
	}
}

func TestSearchVisitsStillBoundCandidateDiscovery(t *testing.T) {
	for _, visits := range []int{100, 100000} {
		result, err := (plan.Planner{Renderer: renderer{}, MaxCandidates: 1, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: visits}}}).Plan(
			context.Background(), manyAppendCandidates(t, 20), []policy.Request{request(t, "192.0.2.2/32")},
		)
		if visits == 100 {
			if !errors.Is(err, policy.ErrBudget) || result != nil {
				t.Fatalf("candidate discovery escaped visits: %v, %v", result, err)
			}
		} else if err != nil || result.Cost().ID != "rule-0000" {
			t.Fatalf("bounded discovery lost cheapest candidate: %v", err)
		}
	}
}

type cancelingRenderer struct{ cancel context.CancelFunc }

func (r cancelingRenderer) Render(context.Context, *fm.Firewall, *fm.Firewall, []plan.Change) ([]string, error) {
	r.cancel()
	return []string{"command after cancellation"}, nil
}

func TestCanceledCandidateCannotReturnPlan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := (plan.Planner{Renderer: cancelingRenderer{cancel: cancel}, MaxCandidates: 1}).Plan(
		ctx, baseline(t), []policy.Request{request(t, "192.0.2.2/32")},
	)
	if result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled candidate returned: %v, %v", result, err)
	}
}
