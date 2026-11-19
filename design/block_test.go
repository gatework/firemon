package design_test

import (
	"slices"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

func blockPlan(t *testing.T, cfg *firemon.Config, in design.Intent) *design.BlockPlan {
	t.Helper()
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := design.New(fw, design.Options{Now: func() time.Time { return now }, Capabilities: firemon.Capabilities{LogDeny: true}}).PlanBlock(in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A block denies the traffic on every zone pair with one rule before the
// first rule that may match it; traffic a deny rule already decides
// everywhere needs nothing; traffic only the default denies gets a rule.
func TestPlanBlock(t *testing.T) {
	t.Parallel()
	in := intent(t, "any", "172.16.0.10", "tcp/445")
	in.Name = ""
	permitAll := rule("1", firemon.ActionPermit, "", "", nil, nil)
	p := blockPlan(t, lab(permitAll), in)
	add, ok := p.Changes[len(p.Changes)-1].(design.AddRule)
	if !ok || !p.Verified || add.Before != "1" || add.Rule.Action != firemon.ActionDeny || add.Rule.Name != "B-20261117-001" ||
		len(add.Rule.From) != 0 || len(add.Rule.To) != 0 || !add.Rule.Log.Deny {
		t.Fatalf("block before the permit: verified %v %q %+v", p.Verified, p.VerifyError, p.Changes)
	}
	denyAll := rule("2", firemon.ActionDeny, "", "", nil, []firemon.AddressRef{inline("172.16.0.0/24")})
	p = blockPlan(t, lab(denyAll, permitAll), in)
	if p.Status != design.StatusNoChange || !slices.Equal(p.BlockedBy, []string{"2"}) {
		t.Fatalf("already blocked by rule 2: %s %v %v", p.Status, p.BlockedBy, p.Changes)
	}
	p = blockPlan(t, lab(), in)
	if p.Status != design.StatusChange || !p.Verified {
		t.Fatalf("only the default denies it: %s %v", p.Status, p.Changes)
	}
}
