package plan_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
)

type batchRenderer struct {
	rejectScope string
	fatal       error
	calls       int
	baseline    string
}

func (r *batchRenderer) Render(ctx context.Context, before, after *fm.Firewall, changes []plan.Change) ([]string, error) {
	r.calls++
	if r.baseline != "" && before.SemanticDigest() != r.baseline {
		return nil, errors.New("renderer did not receive original baseline")
	}
	if r.fatal != nil {
		return nil, r.fatal
	}
	for _, c := range changes {
		if after.Rule(c.Rule).Scope() == r.rejectScope && r.rejectScope != "" {
			return nil, plan.ErrRender
		}
	}
	if err := plan.ValidateChanges(ctx, before, after, changes); err != nil {
		return nil, err
	}
	return []string{after.SemanticDigest()}, nil
}

func TestPlanBatchMultipleContextsAndReadback(t *testing.T) {
	fw := baseline(t)
	a, b := request(t, "192.0.2.2/32"), request(t, "192.0.2.2/32")
	a.Scope = "a"
	b.Scope = "b"
	b.RuleSet = "other"
	r := &batchRenderer{baseline: fw.SemanticDigest()}
	got, err := (plan.Planner{Renderer: r}).PlanBatch(t.Context(), fw, []policy.Request{b, a})
	if err != nil || got.Plan == nil {
		t.Fatalf("batch: %+v %v", got, err)
	}
	if len(got.Inputs) != 2 || got.Inputs[0].Disposition != plan.BatchAccepted || got.Inputs[1].Disposition != plan.BatchAccepted {
		t.Fatal(got.Inputs)
	}
	if len(got.Plan.Changes()) != 2 || len(got.Plan.After().Addresses()) != 3 || len(got.Plan.After().Services()) != 1 {
		t.Fatal("shared objects or context rules lost", got.Plan.Changes())
	}
	if _, err := got.Plan.Verify(t.Context(), got.Plan.After()); err != nil {
		t.Fatal(err)
	}
	d := got.Plan.After().Export()
	d.Rules = d.Rules[1:]
	broken, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.Plan.Verify(t.Context(), broken); !errors.Is(err, plan.ErrReadback) {
		t.Fatal("partial readback accepted", err)
	}
	other, err := (plan.Planner{Renderer: &batchRenderer{}}).PlanBatch(t.Context(), fw, []policy.Request{a, b})
	if err != nil || other.Plan.Digest() != got.Plan.Digest() {
		t.Fatal("input order changed executable plan", err)
	}
	targets := got.Plan.Targets()
	targets[0].Scope = "tampered"
	if got.Plan.Targets()[0].Scope == "tampered" || fw.SemanticDigest() != r.baseline {
		t.Fatal("mutable alias")
	}
}

func TestPlanBatchLocalRejectionAndCoveredProvenance(t *testing.T) {
	fw := baseline(t)
	covered := request(t, "192.0.2.1/32")
	good, bad := request(t, "192.0.2.2/32"), request(t, "192.0.2.3/32")
	bad.Scope = "bad"
	got, err := (plan.Planner{Renderer: &batchRenderer{rejectScope: "bad"}}).PlanBatch(t.Context(), fw, []policy.Request{bad, covered, good})
	if err != nil || got.Plan == nil {
		t.Fatalf("%+v %v", got, err)
	}
	if got.Inputs[0].Disposition != plan.BatchRejected || got.Inputs[1].Disposition != plan.BatchCovered || got.Inputs[2].Disposition != plan.BatchAccepted {
		t.Fatal(got.Inputs)
	}
	if len(got.Inputs[0].Attempts) == 0 || len(got.Plan.Targets()) != 1 {
		t.Fatal("missing refusal or combined targets", got.Inputs)
	}
	for _, r := range got.Plan.After().Rules() {
		if r.Scope() == "bad" {
			t.Fatal("rejected candidate leaked")
		}
	}
	if _, err := got.Plan.Verify(t.Context(), got.Plan.After()); err != nil {
		t.Fatal(err)
	}
}

func TestPlanBatchFatalAndBudgetNeverYieldExecutablePlan(t *testing.T) {
	for _, tc := range []struct {
		name    string
		planner plan.Planner
		ctx     context.Context
		want    error
	}{
		{"fatal", plan.Planner{Renderer: &batchRenderer{fatal: errors.New("dependency unavailable")}}, context.Background(), nil},
		{"budget", plan.Planner{Renderer: &batchRenderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 1}}}, context.Background(), policy.ErrBudget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.planner.PlanBatch(tc.ctx, baseline(t), []policy.Request{request(t, "192.0.2.2/32")})
			if err == nil || got.Plan != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatal(got, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err := (plan.Planner{}).PlanBatch(ctx, baseline(t), []policy.Request{request(t, "192.0.2.1/32")})
	if !errors.Is(err, context.Canceled) || got.Plan != nil {
		t.Fatal(got, err)
	}
}

func TestPlanBatchNormalizesRulesetAndPreservesOldPlan(t *testing.T) {
	fw := baseline(t)
	a := request(t, "192.0.2.2/32")
	b := a
	b.RuleSet = "security"
	p := plan.Planner{Renderer: &batchRenderer{}}
	old, err := p.Plan(t.Context(), fw, []policy.Request{a})
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.PlanBatch(t.Context(), fw, []policy.Request{a, b})
	if err != nil || got.Plan == nil {
		t.Fatal(got, err)
	}
	if len(got.Plan.Targets()) != 1 || len(got.Plan.Changes()) != 1 {
		t.Fatal("compatible requests not grouped")
	}
	again, err := p.Plan(t.Context(), fw, []policy.Request{a})
	if err != nil || old.Digest() != again.Digest() || !reflect.DeepEqual(old.Commands(), again.Commands()) {
		t.Fatal("legacy changed", err)
	}
}

func TestPlanBatchDeterministicPairUnion(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	a, b := request(t, "192.0.2.1/32"), request(t, "192.0.2.2/32")
	box := b.Traffic.Regions()[0]
	box.Destination = addressRange("198.51.100.2/32")
	b.Traffic, err = flow.NewTraffic(32, box)
	if err != nil {
		t.Fatal(err)
	}
	p := plan.Planner{Renderer: &batchRenderer{}}
	first, err := p.PlanBatch(t.Context(), fw, []policy.Request{a, b})
	if err != nil || first.Plan == nil {
		t.Fatal(first, err)
	}
	second, err := p.PlanBatch(t.Context(), fw, []policy.Request{b, a})
	if err != nil || second.Plan == nil {
		t.Fatal(second, err)
	}
	if first.Plan.Digest() != second.Plan.Digest() {
		t.Fatal("equivalent input order changed batch digest")
	}
	cross := a
	box = a.Traffic.Regions()[0]
	box.Destination = addressRange("198.51.100.2/32")
	cross.Traffic, _ = flow.NewTraffic(32, box)
	r, err := (policy.Engine{}).Query(t.Context(), first.Plan.After(), cross)
	if err != nil || !r.Allowed.Empty() {
		t.Fatal("cross-pair expansion", r, err)
	}
}

func TestPlanBatchRejectedDraftDoesNotReserveNames(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	bad, good := request(t, "192.0.2.2/32"), request(t, "192.0.2.2/32")
	bad.Scope = "a"
	good.Scope = "b"
	p := plan.Planner{Renderer: &batchRenderer{rejectScope: "a"}}
	got, err := p.PlanBatch(t.Context(), fw, []policy.Request{bad, good})
	if err != nil || got.Plan == nil {
		t.Fatal(got, err)
	}
	alone, err := p.PlanBatch(t.Context(), fw, []policy.Request{good})
	if err != nil || alone.Plan == nil {
		t.Fatal(alone, err)
	}
	if got.Plan.Digest() != alone.Plan.Digest() {
		t.Fatal("refusal leaked names, objects, changes, or cost")
	}
	if got.Inputs[0].Disposition != plan.BatchRejected || got.Inputs[1].Disposition != plan.BatchAccepted {
		t.Fatal(got.Inputs)
	}
}

func TestPlanBatchDifferentTimeAndEgressMergeSharedRuleChanges(t *testing.T) {
	a, b := request(t, "192.0.2.2/32"), request(t, "192.0.2.3/32")
	a.At = time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	b.At = a.At.Add(time.Hour)
	a.EgressInterface = "a"
	b.EgressInterface = "b"
	got, err := (plan.Planner{Renderer: &batchRenderer{}}).PlanBatch(t.Context(), baseline(t), []policy.Request{a, b})
	if err != nil || got.Plan == nil {
		t.Fatal(got, err)
	}
	if got.Plan.Cost().ModifiedRules != 1 {
		t.Fatal("cost counts candidate attempts rather than final changes", got.Plan.Cost())
	}
	if len(got.Plan.Targets()) != 2 || len(got.Plan.Changes()) != 1 || len(got.Plan.Changes()[0].Sources) != 2 {
		t.Fatal("lost context or duplicated rule change", got.Plan.Targets(), got.Plan.Changes())
	}
	if _, err := got.Plan.Verify(t.Context(), got.Plan.After()); err != nil {
		t.Fatal(err)
	}
}

type selectiveBatchRenderer struct{}

func (selectiveBatchRenderer) Render(_ context.Context, _, after *fm.Firewall, _ []plan.Change) ([]string, error) {
	for _, a := range after.Addresses() {
		for _, r := range a.Record().Ranges {
			if r == addressRange("192.0.2.3/32") {
				return nil, plan.ErrRender
			}
		}
	}
	return []string{"safe"}, nil
}
func TestPlanBatchCombinedRefusalRetainsSameContextSibling(t *testing.T) {
	good, bad := request(t, "192.0.2.2/32"), request(t, "192.0.2.3/32")
	got, err := (plan.Planner{Renderer: selectiveBatchRenderer{}}).PlanBatch(t.Context(), baseline(t), []policy.Request{bad, good})
	if err != nil || got.Plan == nil || got.Inputs[0].Disposition != plan.BatchRejected || got.Inputs[1].Disposition != plan.BatchAccepted {
		t.Fatal(got, err)
	}
	r, err := (policy.Engine{}).Query(t.Context(), got.Plan.After(), bad)
	if err != nil || !r.Allowed.Empty() {
		t.Fatal("rejected traffic became allowed", r, err)
	}
}

func TestPlanBatchIndependentNativeReadbackAcrossZones(t *testing.T) {
	raw := "zone a\nexit\nzone b\nexit\nzone outside\nexit\naddress dst\nip 198.51.100.1/32\nexit\nservice https\ntcp dst-port 443 443\nexit\n"
	fw, err := (hillstone.Parser{}).Parse(t.Context(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fw"})
	if err != nil || !fw.Complete() {
		t.Fatal(fw, err)
	}
	a, b := request(t, "192.0.2.2/32"), request(t, "192.0.2.2/32")
	a.FromZone = "a"
	b.FromZone = "b"
	a.ToZone = "outside"
	b.ToZone = "outside"
	got, err := (plan.Planner{Renderer: hillstone.Renderer{}}).PlanBatch(t.Context(), fw, []policy.Request{a, b})
	if err != nil || got.Plan == nil {
		t.Fatal(got, err)
	}
	source := got.Plan.Changes()[0].Sources[0].ID
	readback := raw + fmt.Sprintf("address %s\nip 192.0.2.2/32\nexit\n", source)
	for i, z := range []string{"b", "a"} {
		readback += fmt.Sprintf("rule id %d\nsrc-zone %s\ndst-zone outside\nsrc-addr %s\ndst-addr dst\nservice https\naction permit\nexit\n", 100+i, z, source)
	}
	observed, err := (hillstone.Parser{}).Parse(t.Context(), config.Source{Text: readback, Complete: true}, fw.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.Plan.Verify(t.Context(), observed); err != nil {
		t.Fatal("independent native readback", err)
	}
}

func TestPlanBatchInvalidZoneIsLocalInputFailure(t *testing.T) {
	good, bad := request(t, "192.0.2.2/32"), request(t, "192.0.2.3/32")
	bad.FromZone = "missing"
	got, err := (plan.Planner{Renderer: &batchRenderer{}}).PlanBatch(t.Context(), baseline(t), []policy.Request{bad, good})
	if err != nil || got.Plan == nil || got.Inputs[0].Disposition != plan.BatchRejected || got.Inputs[1].Disposition != plan.BatchAccepted {
		t.Fatal(got, err)
	}
}

func TestPlanBatchNATPreservationRejectsAppendAndKeepsSafeFallback(t *testing.T) {
	d := baseline(t).Export()
	d.Metadata.Vendor = "netscreen"
	d.NATPools = []fm.NATPoolRecord{{Object: fm.Object{ID: "dip"}, Ranges: []flow.AddressRange{addressRange("203.0.113.1/32")}}}
	d.DynamicNATs = []fm.DynamicNATRecord{{Object: fm.Object{ID: "policy:10"}, Rule: "10", Order: fm.NATOrder{Section: "policy"}, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}, SourceMode: fm.DynamicIP, DestinationMode: fm.NoTranslation, SourcePool: "dip"}}
	d.DynamicNATs[0].Match = d.Rules[0].Match
	fw, err := fm.Seal(d)
	if err != nil || !fw.Complete() {
		t.Fatal(fw, err)
	}
	q := request(t, "192.0.2.2/32")
	got, err := (plan.Planner{Renderer: &batchRenderer{}}).PlanBatch(t.Context(), fw, []policy.Request{q})
	if err != nil || got.Plan == nil {
		t.Fatal(got, err)
	}
	if got.Plan.Changes()[0].Kind != plan.CreateRule || len(got.Inputs[0].Attempts) == 0 || !got.Plan.Proof().NATUnchanged {
		t.Fatal("NAT-changing append accepted", got)
	}
	if err := (policy.Engine{}).PreserveNAT(t.Context(), fw, got.Plan.After(), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := got.Plan.Verify(t.Context(), got.Plan.After()); err != nil {
		t.Fatal(err)
	}
}

func TestPlanBatchFinalFailureAndIncompleteGraphHaveNoPlan(t *testing.T) {
	d := baseline(t).Export()
	d.Rules[0].Match.Unsupported = []string{"unknown condition"}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := (plan.Planner{Renderer: &batchRenderer{}}).PlanBatch(t.Context(), fw, []policy.Request{request(t, "192.0.2.2/32")})
	if got.Plan != nil {
		t.Fatal("unknown graph has executable plan", got, err)
	}
}

func TestPlanBatchForeignRejectionAndLateCancellationAbort(t *testing.T) {
	for _, cause := range []error{&plan.RejectionError{Stage: plan.RepresentationRejection, Err: plan.ErrRender}, fmt.Errorf("dependency: %w", plan.ErrUnsafe), errors.Join(plan.ErrRender, policy.ErrBudget)} {
		r := &batchRenderer{fatal: cause}
		got, err := (plan.Planner{Renderer: r}).PlanBatch(t.Context(), baseline(t), []policy.Request{request(t, "192.0.2.2/32")})
		if !errors.Is(err, cause) || got.Plan != nil || r.calls != 1 {
			t.Fatal("fatal converted to local refusal", got, err, r.calls)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	got, err := (plan.Planner{Renderer: cancelBatchRenderer{cancel}}).PlanBatch(ctx, baseline(t), []policy.Request{request(t, "192.0.2.2/32")})
	if !errors.Is(err, context.Canceled) || got.Plan != nil {
		t.Fatal(got, err)
	}
}

type cancelBatchRenderer struct{ cancel context.CancelFunc }

func (r cancelBatchRenderer) Render(context.Context, *fm.Firewall, *fm.Firewall, []plan.Change) ([]string, error) {
	r.cancel()
	return []string{"too late"}, nil
}

func TestPlanBatchCandidateBudgetIsSharedAndDiscardsProvisionalPlan(t *testing.T) {
	a, b := request(t, "192.0.2.2/32"), request(t, "192.0.2.3/32")
	a.Scope = "a"
	b.Scope = "b"
	got, err := (plan.Planner{Renderer: &batchRenderer{}, MaxCandidates: 1}).PlanBatch(t.Context(), baseline(t), []policy.Request{a, b})
	if !errors.Is(err, policy.ErrBudget) || got.Plan != nil {
		t.Fatal("partial plan escaped exhausted device budget", got, err)
	}
}

func TestPlanBatchFallbackCanonicalizesEquivalentRegionOrder(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	a, b := request(t, "192.0.2.1/32"), request(t, "192.0.2.2/32")
	bad := request(t, "192.0.2.3/32")
	forward, err := flow.NewTraffic(32, a.Traffic.Regions()[0], b.Traffic.Regions()[0])
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := flow.NewTraffic(32, b.Traffic.Regions()[0], a.Traffic.Regions()[0])
	if err != nil {
		t.Fatal(err)
	}
	p := plan.Planner{Renderer: fallbackDigestRenderer{}}
	var results []plan.BatchResult
	for _, traffic := range []flow.Traffic{forward, reverse} {
		good := a
		good.Traffic = traffic
		got, err := p.PlanBatch(t.Context(), fw, []policy.Request{good, bad})
		if err != nil || got.Plan == nil {
			t.Fatal(got, err)
		}
		if len(got.Inputs) != 2 || got.Inputs[0].Index != 0 || got.Inputs[1].Index != 1 || got.Inputs[0].Disposition != plan.BatchAccepted || got.Inputs[1].Disposition != plan.BatchRejected {
			t.Fatal("indexed outcomes changed", got.Inputs)
		}
		if len(got.Inputs[0].Attempts) == 0 || got.Inputs[0].Attempts[0].Stage != plan.RepresentationRejection {
			t.Fatal("combined refusal was not exercised", got.Inputs)
		}
		results = append(results, got)
	}
	first, second := results[0], results[1]
	if first.Plan.After().SemanticDigest() != second.Plan.After().SemanticDigest() {
		t.Error("fallback region order changed final graph digest")
	}
	if first.Plan.Digest() != second.Plan.Digest() {
		t.Error("fallback region order changed approval digest")
	}
	if !reflect.DeepEqual(first.Plan.Commands(), second.Plan.Commands()) {
		t.Error("fallback region order changed native commands")
	}
	for i := range first.Inputs {
		if first.Inputs[i].Index != second.Inputs[i].Index || first.Inputs[i].Disposition != second.Inputs[i].Disposition {
			t.Errorf("input %d disposition changed", i)
		}
	}
}

type fallbackDigestRenderer struct{}

func (fallbackDigestRenderer) Render(ctx context.Context, before, after *fm.Firewall, changes []plan.Change) ([]string, error) {
	if _, err := (selectiveBatchRenderer{}).Render(ctx, before, after, changes); err != nil {
		return nil, err
	}
	return []string{after.SemanticDigest()}, nil
}
