package design_test

import (
	"strings"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// An application deny ahead only acts on part of any traffic: the planner
// still opens the rest, verifies it and warns, instead of giving up.
func TestPlan_NarrowingDenyAheadIsAWarning(t *testing.T) {
	t.Parallel()
	appDeny := rule("9", firemon.ActionDeny, "trust", "dmz", nil, nil)
	appDeny.Applications = []string{"bittorrent"}
	appPermit := rule("8", firemon.ActionPermit, "trust", "dmz", nil, nil)
	appPermit.Applications = []string{"ssh"}
	p := plan(t, lab(appPermit, appDeny), intent(t, "10.0.1.5", "172.16.0.10", "tcp/7777"))
	if p.Status != design.StatusChange || !p.Verified || len(p.Unknown) != 0 {
		t.Fatalf("plan %s verified %v unknown %v: %s", p.Status, p.Verified, p.Unknown, p.VerifyError)
	}
	if len(p.Warnings) == 0 || !strings.Contains(p.Warnings[0], "8,9") {
		t.Fatalf("warnings %v", p.Warnings)
	}
}
