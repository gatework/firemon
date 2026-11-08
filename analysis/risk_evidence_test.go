package analysis_test

import (
	"context"
	"slices"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
)

func TestRiskEvidenceDistinguishesInactiveFromUnknownSchedule(t *testing.T) {
	base := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	for _, known := range []bool{true, false} {
		d := base.Export()
		d.Schedules = []fm.ScheduleRecord{{Object: fm.Object{ID: "maintenance", Spans: []fm.Span{{First: 1, Last: 2}}}, Timezone: "UTC", Windows: []fm.TimeWindow{{Start: at.Add(time.Hour), End: at.Add(2 * time.Hour)}}}}
		if !known {
			d.Schedules[0].Unsupported = []string{"unsupported-calendar"}
		}
		d.Rules[0].Match.Schedule = "maintenance"
		d.Rules[0].Spans = []fm.Span{{First: 3, Last: 5}}
		fw, err := fm.Seal(d)
		if err != nil {
			t.Fatal(err)
		}
		q := request(t, "192.0.2.1", "198.51.100.1")
		q.At = at
		rows, err := (analysis.RiskAnalyzer{}).Analyze(context.Background(), fw, q, analysis.RiskDefinition{ID: "https", Version: "1", Mode: analysis.Effective, Relation: analysis.Intersects, Traffic: q.Traffic})
		if err != nil || len(rows) != 1 {
			t.Fatalf("findings: %+v %v", rows, err)
		}
		evidence := rows[0].Evidence
		if !evidence.At.Equal(at) || evidence.Schedule != "maintenance" || evidence.Timezone != "UTC" || evidence.View != analysis.NativePolicyView || len(evidence.Spans) != 1 {
			t.Fatalf("lost context: %+v", evidence)
		}
		if known {
			if rows[0].Value != analysis.False || evidence.ScheduleActive != analysis.False || !slices.Contains(evidence.Reasons, "schedule-inactive") {
				t.Fatalf("inactive schedule: %+v", rows[0])
			}
		} else if rows[0].Value != analysis.Unknown || evidence.ScheduleActive != analysis.Unknown || !slices.Contains(evidence.Reasons, "schedule-unknown") {
			t.Fatalf("unknown evidence became clean: %+v", rows[0])
		}
		evidence.Spans[0].First = 99
		if fw.Rule(rows[0].Rule).Record().Spans[0].First != 3 {
			t.Fatal("evidence shares graph storage")
		}
	}
}
