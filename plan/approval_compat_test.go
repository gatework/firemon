// Golden approvals captured from e9e9b96, before structural and allocation changes.
package plan_test

import (
	"context"
	"testing"

	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

func TestApprovalDigestRemainsCompatible(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		render    renderer
	}{{"reuse", "192.0.2.1/32", renderer{}}, {"append", "192.0.2.2/32", renderer{}}, {"create", "192.0.2.2/32", renderer{rejectAppend: true}}} {
		p, err := (plan.Planner{Renderer: tc.render}).Plan(context.Background(), baseline(t), []policy.Request{request(t, tc.src)})
		if err != nil {
			t.Fatal(err)
		}
		expected := map[string]string{"reuse": "88b3645167fb4da00bb44e2adff428112d843d020f2043ec6ce5dc644280c62e", "append": "9652e99990c22b434c3ae13918b4e4b0af67cbfdf2d42b73c5e0f87888fc92da", "create": "85d47fb74a4c01ad7c144288adb004acb053d4cee215ecd6bb905a92244217b7"}
		if got := p.Digest(); got != expected[tc.name] {
			t.Fatalf("%s approval digest changed: %s", tc.name, got)
		}
	}
}
