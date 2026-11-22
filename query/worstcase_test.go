package query_test

import (
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
)

// Under ScheduleWorstCase a timed rule in force only part of the period
// counts against the traffic; one in force throughout, or never, is read
// as it is.
func TestEngine_ScheduleWorstCase(t *testing.T) {
	t.Parallel()
	timed := func(r firemon.SecurityRule) firemon.SecurityRule {
		r.Schedule = "nights"
		return r
	}
	tests := []struct {
		name     string
		rules    []firemon.SecurityRule
		activity query.Activity
		want     query.Verdict
	}{
		{"partial deny blocks", []firemon.SecurityRule{timed(deny("1", "", "", "", "", "https")), permit("2", "", "", "", "", "https")}, query.ActivityPartial, query.VerdictDenied},
		{"partial permit does not grant", []firemon.SecurityRule{timed(permit("1", "", "", "", "", "https"))}, query.ActivityPartial, query.VerdictDenied},
		{"permit in force throughout grants", []firemon.SecurityRule{timed(permit("1", "", "", "", "", "https"))}, query.ActivityAlways, query.VerdictAllowed},
		{"deny never in force is skipped", []firemon.SecurityRule{timed(deny("1", "", "", "", "", "https")), permit("2", "", "", "", "", "https")}, query.ActivityNever, query.VerdictAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fw, err := firemon.Compile(lab(firemon.AddressStageOriginal, tt.rules...))
			if err != nil {
				t.Fatal(err)
			}
			e := query.New(fw, query.Options{
				Now: func() time.Time { return at }, Schedules: query.ScheduleWorstCase,
				Activity: func(*firemon.Rule) query.Activity { return tt.activity },
			})
			res, err := e.Query(query.Request{Src: addrs(t, "10.0.0.9"), Dst: addrs(t, "172.16.0.10"), Service: svc(t, "tcp/443"), Strict: true})
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict != tt.want {
				t.Fatalf("got %s, want %s", res.Verdict, tt.want)
			}
		})
	}
}
