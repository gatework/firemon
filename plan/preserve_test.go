package plan_test

import (
	"context"
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/hillstone"
)

func TestPreservationPlanVerifiesWholeGraphAndRejectsIncompleteRemoval(t *testing.T) {
	d := baseline(t).Export()
	d.Rules[0].Disabled = true
	before, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Rules = nil
	after, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	p, err := (plan.Planner{Renderer: hillstone.Renderer{}}).Preserve(context.Background(), before, after, []plan.Change{{Kind: plan.RemoveRule, Rule: "10"}}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if proof, ok := p.Preservation(); !ok || proof.Contexts != 1 {
		t.Fatal("missing whole policy proof", proof)
	}
	if _, err := p.Verify(context.Background(), after); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(context.Background(), before); !errors.Is(err, plan.ErrReadback) {
		t.Fatal("deleted rule still present", err)
	}
	if len(p.Commands()) != 3 || p.Commands()[1] != "no rule id 10" {
		t.Fatal(p.Commands())
	}
}
