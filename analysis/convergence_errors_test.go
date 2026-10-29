package analysis_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
)

type failingConvergenceRenderer struct {
	err   error
	calls int
}

func TestConvergenceRejectsForeignRejectionErrors(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}})
	for _, cause := range []error{policy.ErrNotEquivalent, plan.ErrRender} {
		foreign := &plan.RejectionError{Stage: plan.PreservationRejection, Err: cause}
		for _, failure := range []error{foreign, fmt.Errorf("renderer dependency: %w", foreign)} {
			native := &failingConvergenceRenderer{err: failure}
			rows, err := (analysis.Converger{Planner: plan.Planner{Renderer: native}}).Candidates(context.Background(), fw, time.Time{})
			var diagnostic *plan.RejectionError
			if rows != nil || native.calls != 1 || !errors.Is(err, failure) || !errors.As(err, &diagnostic) || diagnostic != foreign {
				t.Fatalf("foreign rejection lost provenance or diagnostics: rows=%d calls=%d err=%v", len(rows), native.calls, err)
			}
		}
	}
}

func TestConvergenceRetainsExpectedRejectionStages(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pairs    [][2]string
		deny     bool
		renderer plan.Renderer
		stage    plan.RejectionStage
		cause    error
	}{
		{"cross pairs", [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.2"}}, false, hillstone.Renderer{}, plan.DeclarationRejection, plan.ErrUnsafe},
		{"deny shadowing", [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}}, true, hillstone.Renderer{}, plan.PreservationRejection, policy.ErrNotEquivalent},
		{"unsupported representation", [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}}, false, &failingConvergenceRenderer{err: plan.ErrRender}, plan.RepresentationRejection, plan.ErrRender},
		{"empty commands", [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}}, false, &failingConvergenceRenderer{}, plan.RepresentationRejection, plan.ErrUnsafe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := graph(t, tc.pairs)
			if tc.deny {
				d := fw.Export()
				d.Rules[1].Action = fm.Deny
				var err error
				fw, err = fm.Seal(d)
				if err != nil {
					t.Fatal(err)
				}
			}
			converger := analysis.Converger{Planner: plan.Planner{Renderer: tc.renderer}}
			rows, err := converger.Candidates(context.Background(), fw, time.Time{})
			if err != nil || len(rows) != 1 || rows[0].Plan != nil {
				t.Fatalf("expected refusal missing: %v %v", rows, err)
			}
			var rejection *plan.RejectionError
			if !errors.As(rows[0].Rejection, &rejection) || rejection.Stage != tc.stage || !errors.Is(rejection, tc.cause) {
				t.Fatalf("wrong rejection: %v", rows[0].Rejection)
			}
			_, err = converger.Plan(context.Background(), fw, rows[0].Rules, time.Time{})
			if !errors.As(err, &rejection) || rejection.Stage != tc.stage || !errors.Is(err, tc.cause) {
				t.Fatalf("direct plan lost rejection: %v", err)
			}
		})
	}
}

func (r *failingConvergenceRenderer) Render(context.Context, *fm.Firewall, *fm.Firewall, []plan.Change) ([]string, error) {
	r.calls++
	return nil, r.err
}

func TestConvergenceCandidatesAbortOnOperationalFailure(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}})
	for _, cause := range []error{
		errors.New("renderer dependency unavailable"),
		fmt.Errorf("renderer fault: %w", plan.ErrUnsafe),
		fmt.Errorf("renderer fault: %w", policy.ErrNotEquivalent),
		errors.Join(plan.ErrRender, policy.ErrBudget),
		errors.Join(plan.ErrRender, flow.ErrBudget),
		errors.Join(plan.ErrRender, context.Canceled),
		context.DeadlineExceeded,
	} {
		t.Run(cause.Error(), func(t *testing.T) {
			native := &failingConvergenceRenderer{err: cause}
			rows, err := (analysis.Converger{Planner: plan.Planner{Renderer: native}}).Candidates(context.Background(), fw, time.Time{})
			if rows != nil || !errors.Is(err, cause) || native.calls != 1 {
				t.Fatalf("operational failure hidden or retried: rows=%d calls=%d err=%v", len(rows), native.calls, err)
			}
		})
	}
	rows, err := (analysis.Converger{}).Candidates(context.Background(), fw, time.Time{})
	if rows != nil || !errors.Is(err, plan.ErrInvalid) {
		t.Fatalf("missing renderer hidden as a rejection: rows=%d err=%v", len(rows), err)
	}
}
