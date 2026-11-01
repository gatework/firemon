package benchmarks_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/huawei"
)

type countingBusinessRenderer struct{ calls int }

func (r *countingBusinessRenderer) Render(ctx context.Context, before, after *fm.Firewall, changes []plan.Change) ([]string, error) {
	r.calls++
	return (huawei.Renderer{}).Render(ctx, before, after, changes)
}
func businessCandidateGraph(tb testing.TB, n int, sparse bool) *fm.Firewall {
	tb.Helper()
	d := benchmarkFirewall(tb, n).Export()
	var match fm.Match
	for _, r := range d.Rules {
		if !r.Builtin {
			match = r.Match
			break
		}
	}
	for i := range d.Rules {
		if d.Rules[i].Builtin {
			continue
		}
		if sparse {
			d.Rules[i].Description = fmt.Sprintf("separate-intent-%d", i)
		} else {
			d.Rules[i].Match = match
		}
	}
	fw, err := fm.Seal(d)
	if err != nil {
		tb.Fatal(err)
	}
	return fw
}

// Sparse returns the same successful empty result on both versions with an
// adequate equal comparison cap. DenseProbe proves exactly one compatible pair
// then refuses the next; it does NOT measure full dense enumeration throughput.
func BenchmarkBusinessCandidates(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		for _, sparse := range []bool{true, false} {
			name := "dense-probe"
			if sparse {
				name = "sparse"
			}
			b.Run(fmt.Sprintf("%s/rules=%d", name, n), func(b *testing.B) {
				fw := businessCandidateGraph(b, n, sparse)
				renderer := &countingBusinessRenderer{}
				cap := 1
				if sparse {
					cap = n * (n - 1) / 2
				}
				c := analysis.Converger{MaxComparisons: cap, Planner: plan.Planner{Renderer: renderer, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 10000000, MaxCombinations: 1000000}}}}
				b.ReportAllocs()
				for b.Loop() {
					renderer.calls = 0
					rows, err := c.Candidates(context.Background(), fw, time.Time{})
					if sparse {
						if err != nil || len(rows) != 0 || renderer.calls != 0 {
							b.Fatal(rows, err, renderer.calls)
						}
					} else if !errors.Is(err, policy.ErrBudget) || len(rows) != 0 || renderer.calls != 1 {
						b.Fatal("dense probe did not prove exactly one pair", err, renderer.calls)
					}
				}
			})
		}
	}
}

func BenchmarkBusinessSharedGroups(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("rules=%d/members=16", n), func(b *testing.B) {
			d := benchmarkFirewall(b, n).Export()
			var members []fm.AddressRef
			for _, r := range d.Rules {
				if !r.Builtin && len(members) < 16 {
					members = append(members, r.Match.Sources[0])
				}
			}
			d.AddressGroups = append(d.AddressGroups, fm.AddressGroupRecord{Object: fm.Object{ID: "shared-16", Name: "shared-16"}, Members: members})
			for i := range d.Rules {
				if !d.Rules[i].Builtin {
					d.Rules[i].Match.Sources = []fm.AddressRef{{Kind: fm.AddressGroupObject, ID: "shared-16"}}
				}
			}
			fw, err := fm.Seal(d)
			if err != nil {
				b.Fatal(err)
			}
			r := analysis.Reclaimer{Planner: plan.Planner{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: n * 1000, MaxCombinations: n * 100, MaxRegions: n * 100}}}}
			b.ReportAllocs()
			for b.Loop() {
				rows, err := r.AnalyzeMembers(context.Background(), fw, analysis.ReclamationRequest{})
				if err != nil || len(rows) != n*18 {
					b.Fatal(len(rows), err)
				}
				for _, row := range rows {
					if row.Unused != analysis.Unknown {
						b.Fatal("unknown observation became unused")
					}
				}
			}
		})
	}
}
