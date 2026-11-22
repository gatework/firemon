package design_test

import (
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/query"
)

// Temporary access ends at Until: through the rule's validity window where
// the vendor has one, else through a one-time schedule the plan creates.
// Either way the access holds now and is gone after Until.
func TestPlan_Until(t *testing.T) {
	t.Parallel()
	until := now.Add(48 * time.Hour)
	for _, tt := range []struct {
		name     string
		windows  bool
		schedule bool
	}{
		{"validity window", true, false},
		{"one-time schedule", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fw, err := firemon.Compile(lab())
			if err != nil {
				t.Fatal(err)
			}
			in := intent(t, "10.0.1.5", "172.16.0.10", "tcp/22")
			in.Until = until
			p, err := design.New(fw, design.Options{Now: func() time.Time { return now }, Capabilities: firemon.Capabilities{RuleWindows: tt.windows}}).Plan(in)
			if err != nil || !p.Verified {
				t.Fatalf("plan %v verified %v: %s %v", err, p.Verified, p.VerifyError, p.Unknown)
			}
			var schedule bool
			var window firemon.TimeWindow
			for _, c := range p.Changes {
				switch x := c.(type) {
				case design.AddSchedule:
					schedule = true
				case design.AddRule:
					window = x.Rule.Window
				}
			}
			if schedule != tt.schedule || (tt.windows && !window.End.Equal(until)) {
				t.Fatalf("changes %v", p.Changes)
			}
			cfg := fw.Config()
			if err := design.Apply(cfg, p.Changes); err != nil {
				t.Fatal(err)
			}
			after, err := firemon.Compile(cfg)
			if err != nil {
				t.Fatal(err)
			}
			e := query.New(after, query.Options{})
			req := query.Request{Src: in.Src, Dst: in.Dst, Service: in.Service}
			for at, want := range map[time.Time]query.Verdict{now: query.VerdictAllowed, until.Add(time.Hour): query.VerdictDenied} {
				req.At = at
				if res, err := e.Query(req); err != nil || res.Verdict != want {
					t.Fatalf("at %s: %v %v, want %s", at, err, res.Verdict, want)
				}
			}
		})
	}
}
