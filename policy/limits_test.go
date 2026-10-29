package policy_test

import (
	"testing"

	"github.com/gatework/firemon/policy"
)

func TestLimitsWithDefaultsPreservesConfiguredValuesAndInput(t *testing.T) {
	for _, tc := range []struct {
		name        string
		input, want policy.Limits
	}{
		{"zero", policy.Limits{}, policy.Limits{MaxRegions: 4096, MaxVisits: 100000, MaxCombinations: 4096}},
		{"mixed", policy.Limits{MaxRegions: 1, MaxVisits: -1, MaxCombinations: 9000}, policy.Limits{MaxRegions: 1, MaxVisits: 100000, MaxCombinations: 9000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.input
			if got := tc.input.WithDefaults(); got != tc.want {
				t.Fatalf("limits = %+v, want %+v", got, tc.want)
			}
			if tc.input != before {
				t.Fatal("normalization changed caller limits")
			}
		})
	}
}
