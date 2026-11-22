package design_test

import (
	"strings"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// A preceding application deny can block the entire requested connection.
func TestPlan_NarrowingDenyLeavesAccessUnproven(t *testing.T) {
	t.Parallel()
	appDeny := rule("9", firemon.ActionDeny, "trust", "dmz", nil, nil)
	appDeny.Conditions = []firemon.Condition{firemon.ApplicationCondition("bittorrent")}
	appPermit := rule("8", firemon.ActionPermit, "trust", "dmz", nil, nil)
	appPermit.Conditions = []firemon.Condition{firemon.ApplicationCondition("ssh")}
	p := plan(t, lab(appPermit, appDeny), intent(t, "10.0.1.5", "172.16.0.10", "tcp/7777"))
	if p.Status != design.StatusIndeterminate || p.Verified || len(p.Changes) != 0 {
		t.Fatalf("plan %s verified %v unknown %v: %s", p.Status, p.Verified, p.Unknown, p.VerifyError)
	}
	if len(p.Unknown) == 0 || !strings.Contains(p.Unknown[0], "9") {
		t.Fatalf("uncertainty must identify the deny rule: %v", p.Unknown)
	}
}
