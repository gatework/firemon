package operations_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors"
)

// The same benchmark source runs against the frozen and refactored modules.
// Fixture parsing, snapshot publication and initial proof are outside the loop.
func BenchmarkIntentLifecycle(b *testing.B) {
	store, revision, finite := finiteReconstructionPlan(b)
	renderer, err := vendors.Renderer(finite.Before().Metadata().Vendor)
	if err != nil {
		b.Fatal(err)
	}
	planner := plan.Planner{Renderer: renderer, NativeRenderer: renderer.(plan.NativeRenderer)}
	policyInputs, nativeInputs := finite.InputRequests(), finite.NativeInputs()
	ordinary, err := planner.PlanBatch(b.Context(), finite.Before(), policyInputs)
	if err != nil || ordinary.Plan == nil {
		b.Fatal("policy fixture", err)
	}
	for _, tc := range []struct {
		name string
		p    *plan.Plan
	}{
		{"policy", ordinary.Plan},
		{"finite", finite},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var material bytes.Buffer
			sum, err := plan.EncodeReconstruction(b.Context(), &material, plan.SnapshotRevisions{Baseline: revision}, tc.p)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("Plan", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var result plan.BatchResult
					if tc.name == "policy" {
						result, err = planner.PlanBatch(b.Context(), finite.Before(), policyInputs)
					} else {
						result, err = planner.PlanNativeBatch(b.Context(), finite.Before(), nativeInputs)
					}
					if err != nil || result.Plan == nil || result.Plan.Digest() != tc.p.Digest() {
						b.Fatal("planning changed", err)
					}
				}
			})
			b.Run("Encode", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					got, err := plan.EncodeReconstruction(b.Context(), io.Discard, plan.SnapshotRevisions{Baseline: revision}, tc.p)
					if err != nil || got != sum {
						b.Fatal("encoding changed", err)
					}
				}
			})
			b.Run("Restore", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					p, got, err := operations.RestorePlan(b.Context(), bytes.NewReader(material.Bytes()), sum, store)
					if err != nil || got != revision || p == nil || p.Digest() != tc.p.Digest() {
						b.Fatal("reconstruction changed", err)
					}
				}
			})
		})
	}
}
