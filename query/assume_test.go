package query_test

import (
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
)

// Rules by user and URL category are settled by the request's criteria, or
// taken not to match with the premise recorded (ADR 0017).
func TestConditions_Premises(t *testing.T) {
	t.Parallel()
	byUser := permit("ops", "", "", "", "")
	byUser.Conditions = []firemon.Condition{firemon.Criterion(firemon.ConditionUser, `user "ops"`, "ops")}
	byURL := deny("news", "", "", "", "")
	byURL.Conditions = []firemon.Condition{firemon.Criterion(firemon.ConditionURLCategory, `url-category "news"`, "news")}
	cfg := lab(firemon.AddressStageOriginal, byURL, byUser)
	cfg.Applications = firemon.ServiceBook{
		"ssh":   {firemon.PortEntry(6, portOf(22))},
		"https": {firemon.PortEntry(6, portOf(443))},
	}
	base := query.Request{Src: addrs(t, "10.0.0.9"), Dst: addrs(t, "203.0.113.208")}
	tests := []struct {
		name        string
		service     string
		users, cats []string
		strict      bool
		want        query.Verdict
		conditional []string
	}{
		{"no user given: the user rule is taken not to match", "tcp/22", nil, nil, false, query.VerdictDenied, []string{"ops"}},
		{"a matching user permits", "tcp/22", []string{"OPS"}, nil, false, query.VerdictAllowed, nil},
		{"another user does not match", "tcp/22", []string{"dev"}, nil, false, query.VerdictDenied, nil},
		{"URL category: on web traffic it is a premise", "tcp/443", []string{"ops"}, nil, false, query.VerdictAllowed, []string{"news"}},
		{"URL category: a matching category denies", "tcp/443", []string{"ops"}, []string{"news"}, false, query.VerdictDenied, nil},
		{"strict: both stay possible", "tcp/22", nil, nil, true, query.VerdictIndeterminate, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := base
			req.Service, req.Users, req.URLCategories, req.Strict = svc(t, tt.service), tt.users, tt.cats, tt.strict
			res := queryOne(t, cfg, req)
			if res.Verdict != tt.want {
				t.Fatalf("got %s, want %s", res.Verdict, tt.want)
			}
			var got []string
			for _, p := range res.Paths {
				for _, d := range p.Decisions {
					for _, r := range d.Conditional() {
						got = append(got, r.ID())
					}
				}
			}
			if len(got) != len(tt.conditional) || (len(got) > 0 && got[0] != tt.conditional[0]) {
				t.Fatalf("conditional premises %v, want %v", got, tt.conditional)
			}
		})
	}
}

// A rule its schedule keeps inactive at the instant evaluated is a premise:
// at night it would deny.
func TestConditions_SchedulePremise(t *testing.T) {
	t.Parallel()
	night := deny("night", "", "", "", "")
	night.Schedule = "nights"
	cfg := lab(firemon.AddressStageOriginal, night, permit("rest", "", "", "", ""))
	noon := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	res := queryOne(t, cfg, query.Request{Src: addrs(t, "10.0.0.9"), Dst: addrs(t, "203.0.113.208"), Service: svc(t, "tcp/22"), At: noon})
	if res.Verdict != query.VerdictAllowed {
		t.Fatalf("got %s", res.Verdict)
	}
	d := res.Paths[0].Decisions[0]
	if c := d.Conditional(); len(c) != 1 || c[0].ID() != "night" {
		t.Fatalf("premises %v", c)
	}
}
