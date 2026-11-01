package vendors_test

import (
	"bytes"
	"testing"

	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/snapshot"
)

func TestNativeCreationDurableReconstruction(t *testing.T) {
	for _, tc := range nativeCases() {
		t.Run(tc.name, func(t *testing.T) {
			before, after, planner, input, _ := nativePlanFixture(t, tc)
			result, err := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{input})
			if err != nil || result.Plan == nil {
				t.Fatal(result, err)
			}
			store, err := snapshot.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			revision, err := store.Archive(t.Context(), before)
			if err != nil {
				t.Fatal(err)
			}
			var b bytes.Buffer
			sum, err := operations.EncodePlan(t.Context(), &b, revision, result.Plan)
			if err != nil {
				t.Fatal(err)
			}
			p, gotRevision, err := operations.RestorePlan(t.Context(), &b, sum, store)
			if err != nil || gotRevision != revision || p.Digest() != result.Plan.Digest() || len(p.NativeInputs()[0].NAT) != len(input.NAT) {
				t.Fatal("native reconstruction", err)
			}
			if _, err := p.Verify(t.Context(), after); err != nil {
				t.Fatal("restored independent readback", err)
			}
		})
	}
}
