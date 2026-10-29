package plan_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

type retainingRenderer struct{ retained []plan.Change }

func (r *retainingRenderer) Render(_ context.Context, _, _ *fm.Firewall, changes []plan.Change) ([]string, error) {
	r.retained = changes
	return []string{"reviewed native commands"}, nil
}

func TestRendererCannotMutateSealedTransferChanges(t *testing.T) {
	native := &retainingRenderer{}
	result, err := (plan.Planner{Renderer: native}).Transfer(context.Background(), baseline(t), []plan.RuleIntent{{
		Request: request(t, "192.0.2.2/32"), Action: fm.Permit,
		Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant,
	}}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	before, digest := result.Changes(), result.Digest()
	native.retained[0].Rule = "unrelated-rule"
	native.retained[0].Sources[0].ID = "unrelated-address"
	native.retained[0].Services[0].ID = "unrelated-service"
	if !reflect.DeepEqual(result.Changes(), before) || result.Digest() != digest {
		t.Fatal("renderer changed sealed plan through retained arguments")
	}
	if err := plan.ValidateChanges(context.Background(), result.Before(), result.After(), result.Changes()); err != nil {
		t.Fatal("sealed delta no longer describes proven graph:", err)
	}
}

func TestAllPlanningEntriesRejectCancellationAfterRendering(t *testing.T) {
	data := baseline(t).Export()
	data.Rules[0].Disabled = true
	before, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	data.Rules = nil
	after, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"plan", "transfer", "preserve"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			planner := plan.Planner{Renderer: cancelingRenderer{cancel: cancel}}
			var result *plan.Plan
			var err error
			switch kind {
			case "plan":
				result, err = planner.Plan(ctx, before, []policy.Request{request(t, "192.0.2.2/32")})
			case "transfer":
				result, err = planner.Transfer(ctx, before, []plan.RuleIntent{{
					Request: request(t, "192.0.2.2/32"), Action: fm.Permit,
					Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant,
				}}, time.Time{})
			case "preserve":
				result, err = planner.Preserve(ctx, before, after, []plan.Change{{Kind: plan.RemoveRule, Rule: "10"}}, time.Time{})
			}
			if !errors.Is(err, context.Canceled) || result != nil {
				t.Fatalf("canceled rendering returned plan=%v, err=%v", result != nil, err)
			}
		})
	}
}
