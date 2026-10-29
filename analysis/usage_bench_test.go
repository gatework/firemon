package analysis_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
)

func BenchmarkReclaimerUsage(b *testing.B) {
	for _, count := range []int{10, 1000} {
		for _, samples := range []int{2, 16} {
			b.Run(fmt.Sprintf("rules=%d/samples=%d", count, samples), func(b *testing.B) {
				d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}}
				for i := 0; i < count; i++ {
					d.Rules = append(d.Rules, fm.RuleRecord{Object: fm.Object{ID: fm.ID(fmt.Sprint(i))}, RuleSet: "security", Position: i, Disabled: true, Action: fm.Permit, Log: fm.Irrelevant, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}})
				}
				fw, err := fm.Seal(d)
				if err != nil {
					b.Fatal(err)
				}
				at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				req := analysis.ReclamationRequest{At: at, Revision: "current", Window: fm.TimeWindow{Start: at.Add(-time.Duration(samples) * time.Hour), End: at}}
				for _, r := range fw.Rules() {
					identity, _ := analysis.IdentifyRule(fw, r.ID())
					digest, _ := analysis.RuleDigest(fw, r.ID())
					for j := 0; j < samples; j++ {
						end := at.Add(-time.Duration(j) * time.Hour)
						req.Observations = append(req.Observations, analysis.UsageObservation{Identity: identity, Revision: req.Revision, RuleDigest: digest, Source: "counter", Start: end.Add(-time.Hour), End: end, Complete: true})
					}
				}
				reclaimer := analysis.Reclaimer{}
				b.ReportAllocs()
				for b.Loop() {
					rows, err := reclaimer.Analyze(context.Background(), fw, req)
					if err != nil || len(rows) != count || rows[0].Unused != analysis.True {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
