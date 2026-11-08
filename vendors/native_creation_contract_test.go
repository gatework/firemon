package vendors_test

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors"
)

// These synthetic fixtures pin the full native command sequence, including
// syntax outside the selected excerpts in independent native capture tests.
func TestNativeCreationCommandsAndApproval(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-commands.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]struct {
		Commands []string `json:"commands"`
	}
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	if len(expected) != len(nativeCases()) {
		t.Fatal("native command fixture count changed")
	}
	for _, tc := range nativeCases() {
		t.Run(tc.name, func(t *testing.T) {
			before := nativeParse(t, tc.vendor, tc.version, tc.before)
			after := nativeParse(t, tc.vendor, tc.version, tc.before+tc.after)
			r, _ := vendors.Renderer(tc.vendor)
			commands, err := r.(plan.NativeRenderer).RenderNative(t.Context(), before, after, nativeDelta(before, after))
			if err != nil || !slices.Equal(commands, expected[tc.name].Commands) {
				t.Fatalf("commands drift: %v\ngot %q\nwant %q", err, commands, expected[tc.name].Commands)
			}
			base, _, planner, input, _ := nativePlanFixture(t, tc)
			result, err := planner.PlanNativeBatch(t.Context(), base, []plan.NativeRequest{input})
			if err != nil || result.Plan == nil {
				t.Fatal("native plan", err)
			}
			repeated, err := planner.PlanNativeBatch(t.Context(), base, []plan.NativeRequest{input})
			if err != nil || repeated.Plan == nil || repeated.Plan.Digest() != result.Plan.Digest() {
				t.Fatal("approval is not deterministic", err)
			}
			if _, err := result.Plan.Verify(t.Context(), result.Plan.After()); err != nil {
				t.Fatal("approval proof", err)
			}
		})
	}
}
