package plan_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/paloalto"
)

// Each planning intent charges its change-safety proof and owned nested
// declarations against one visit allowance. These profiles pin the published
// cumulative accounting, for a fixed input, at every allowance where
// the observable outcome changes, so a restructured proof that reorders or
// resizes a charge, or reorders a refusal before or after a charge, fails here.
func TestPlanningIntentBudgetProfiles(t *testing.T) {
	for _, c := range budgetProfileCases(t) {
		t.Run(c.name, func(t *testing.T) {
			if got := budgetProfile(t, c.run); got != c.expected {
				t.Fatalf("budget profile changed\n got: %s\nwant: %s", got, c.expected)
			}
		})
	}
}

type budgetProfileCase struct {
	name, expected string
	run            func(ctx context.Context, engine policy.Engine) string
}

// budgetProfile sweeps the visit allowance upward until the outcome matches the
// outcome under default limits, recording each allowance where it changes.
func budgetProfile(t *testing.T, run func(context.Context, policy.Engine) string) string {
	t.Helper()
	const sweepLimit = 20_000
	final := run(t.Context(), policy.Engine{})
	var transitions []string
	previous := ""
	for visits := 1; visits <= sweepLimit; visits++ {
		got := run(t.Context(), policy.Engine{Limits: policy.Limits{MaxVisits: visits}})
		if got != previous {
			transitions = append(transitions, fmt.Sprintf("%d:%s", visits, got))
			previous = got
		}
		if got == final && got != "budget" {
			return strings.Join(transitions, " ")
		}
	}
	t.Fatalf("outcome %q not reached within %d visits: %v", final, sweepLimit, transitions)
	return ""
}

// outcomeOf names an entry point's observable outcome class.
func outcomeOf(err error) string {
	var migration *plan.MigrationError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, policy.ErrBudget):
		return "budget"
	case errors.As(err, &migration):
		return "migration:" + migration.Issue.Code
	case errors.Is(err, plan.ErrUnsafe):
		return "unsafe"
	case errors.Is(err, plan.ErrInvalid):
		return "invalid"
	case errors.Is(err, plan.ErrRender):
		return "render"
	default:
		return "error:" + err.Error()
	}
}

func batchOutcome(result plan.BatchResult, err error) string {
	if err != nil {
		return outcomeOf(err)
	}
	var dispositions []string
	for _, input := range result.Inputs {
		dispositions = append(dispositions, fmt.Sprint(input.Disposition))
	}
	return fmt.Sprintf("batch[%s]plan=%v", strings.Join(dispositions, ","), result.Plan != nil)
}

const profileZones = "set zone inside network layer3 ethernet1/1\n" +
	"set zone outside network layer3 ethernet1/2\n" +
	"set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24\n" +
	"set network interface ethernet ethernet1/2 layer3 ip 198.51.100.1/24\n" +
	"set address src ip-netmask 192.0.2.10/32\n" +
	"set address dst ip-netmask 198.51.100.10/32\n"

func profileGraph(t *testing.T, raw string) *fm.Firewall {
	t.Helper()
	fw, err := (paloalto.Parser{}).Parse(t.Context(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"})
	if err != nil || !fw.Complete() {
		t.Fatal(err, fw.Diagnostics())
	}
	return fw
}

// withIrrelevantLogging establishes that native logging does not affect the
// migration, as a captured source with known logging evidence would.
func withIrrelevantLogging(t *testing.T, fw *fm.Firewall) *fm.Firewall {
	t.Helper()
	d := fw.Export()
	for i := range d.Rules {
		d.Rules[i].Log, d.Rules[i].LogStart, d.Rules[i].LogEnd = fm.Irrelevant, fm.Irrelevant, fm.Irrelevant
	}
	sealed, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func profileRule(name, action string) string {
	var b strings.Builder
	for _, field := range []string{"from inside", "to outside", "source src", "destination dst", "application any", "service any", "action " + action} {
		fmt.Fprintf(&b, "set rulebase security rules %s %s\n", name, field)
	}
	return b.String()
}

func budgetProfileCases(t *testing.T) []budgetProfileCase {
	t.Helper()
	zoned := func(source string) policy.Request {
		q := request(t, source)
		q.FromZone, q.ToZone = "inside", "outside"
		return q
	}
	ruleIntent := func(q policy.Request, action fm.Action) plan.RuleIntent {
		return plan.RuleIntent{Request: q, Action: action, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}
	}
	pan := profileGraph(t, profileZones)
	source := withIrrelevantLogging(t, profileGraph(t, profileZones+profileRule("allow-web", "allow")))
	shadowed := profileGraph(t, profileZones+profileRule("block-web", "deny"))
	coordinate := plan.MigrationContext{Chain: fm.PolicyChain{RuleSet: "security"}, FromZone: "inside", ToZone: "outside"}
	migration := plan.MigrationInput{Contexts: []plan.MigrationContextMapping{{Source: coordinate, Target: coordinate}}}
	reverse := plan.MigrationContext{Chain: coordinate.Chain, FromZone: "outside", ToZone: "inside"}
	overlapping := plan.MigrationInput{Contexts: []plan.MigrationContextMapping{{Source: coordinate, Target: coordinate}, {Source: coordinate, Target: reverse}}}
	return []budgetProfileCase{
		{name: "access append", expected: "1:budget 36:ok", run: func(ctx context.Context, engine policy.Engine) string {
			_, err := (plan.Planner{Renderer: renderer{}, Engine: engine}).Plan(ctx, baseline(t), []policy.Request{request(t, "192.0.2.2/32")})
			return outcomeOf(err)
		}},
		{name: "access new rule", expected: "1:budget 66:ok", run: func(ctx context.Context, engine policy.Engine) string {
			_, err := (plan.Planner{Renderer: renderer{rejectAppend: true}, Engine: engine}).Plan(ctx, baseline(t), []policy.Request{request(t, "192.0.2.2/32")})
			return outcomeOf(err)
		}},
		{name: "transfer", expected: "1:budget 129:ok", run: func(ctx context.Context, engine policy.Engine) string {
			intents := []plan.RuleIntent{ruleIntent(zoned("192.0.2.1/32"), fm.Drop), ruleIntent(zoned("192.0.2.2/32"), fm.Permit)}
			_, err := (plan.Planner{Renderer: paloalto.Renderer{}, Engine: engine}).Transfer(ctx, pan, intents, time.Time{})
			return outcomeOf(err)
		}},
		{name: "transfer contradictory", expected: "1:budget 46:unsafe", run: func(ctx context.Context, engine policy.Engine) string {
			q := request(t, "192.0.2.1/32")
			intents := []plan.RuleIntent{ruleIntent(q, fm.Permit), ruleIntent(q, fm.Deny)}
			_, err := (plan.Planner{Renderer: renderer{}, Engine: engine}).Transfer(ctx, baseline(t), intents, time.Time{})
			return outcomeOf(err)
		}},
		{name: "policy batch", expected: "1:budget 306:batch[accepted,accepted]plan=true", run: func(ctx context.Context, engine policy.Engine) string {
			a, b := request(t, "192.0.2.2/32"), request(t, "192.0.2.2/32")
			a.Scope, b.Scope, b.RuleSet = "a", "b", "other"
			return batchOutcome((plan.Planner{Renderer: &batchRenderer{}, Engine: engine}).PlanBatch(ctx, baseline(t), []policy.Request{b, a}))
		}},
		{name: "native batch", expected: "1:budget 123:batch[accepted]plan=true", run: func(ctx context.Context, engine policy.Engine) string {
			return batchOutcome((plan.Planner{NativeRenderer: nativeRenderer{}, Engine: engine}).PlanNativeBatch(ctx, baseline(t), []plan.NativeRequest{nativeInput(t)}))
		}},
		{name: "migration", expected: "1:budget 148:ok", run: func(ctx context.Context, engine policy.Engine) string {
			_, err := (plan.Planner{Renderer: renderer{}, Engine: engine}).Migrate(ctx, source, pan, migration)
			return outcomeOf(err)
		}},
		{name: "migration before existing deny", expected: "1:budget 172:ok", run: func(ctx context.Context, engine policy.Engine) string {
			_, err := (plan.Planner{Renderer: renderer{}, Engine: engine}).Migrate(ctx, source, shadowed, migration)
			return outcomeOf(err)
		}},
		{name: "migration repeated source context", expected: "1:budget 79:invalid", run: func(ctx context.Context, engine policy.Engine) string {
			_, err := (plan.Planner{Renderer: renderer{}, Engine: engine}).Migrate(ctx, source, pan, overlapping)
			return outcomeOf(err)
		}},
	}
}
