package plan_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

// All intent families use the same approval boundary while preserving their
// distinct proof contracts and public report meaning.
func TestIntentApprovalAndReports(t *testing.T) {
	for _, mode := range []string{"reuse", "append", "create", "batch", "batch-covered", "native", "native-partial", "preserve", "preserve-unchanged", "transfer"} {
		t.Run(mode, func(t *testing.T) {
			p := intentFixture(t, mode)
			repeated := intentFixture(t, mode)
			if p.Digest() == "" || p.Digest() != repeated.Digest() {
				t.Fatal("nondeterministic approval")
			}
			readback, err := p.Verify(t.Context(), p.After())
			if err != nil {
				t.Fatal(err)
			}
			if readback.PlanDigest != p.Digest() || readback.ObservedDigest != p.After().SemanticDigest() {
				t.Fatal("readback not bound to approval")
			}
			if err := p.VerifyBaseline(t.Context(), p.Before()); err != nil {
				t.Fatal(err)
			}
			proof := p.Proof()
			if proof.BaseDigest != p.Before().SemanticDigest() || proof.ResultDigest != p.After().SemanticDigest() || !proof.OutsidePreserved {
				t.Fatal("proof graph boundary", proof)
			}
			preservation, preserved := p.Preservation()
			wantPreserved := strings.HasPrefix(mode, "preserve")
			if preserved != wantPreserved {
				t.Fatal("wrong verification contract")
			}
			if preserved && (preservation.BaseDigest != proof.BaseDigest || preservation.ResultDigest != proof.ResultDigest || preservation.Contexts < 1) {
				t.Fatal("equivalence proof lost")
			}
			noChanges := mode == "reuse" || mode == "batch-covered" || mode == "preserve-unchanged"
			if (len(p.Changes()) == 0) != noChanges || (len(p.Commands()) == 0) != noChanges {
				t.Fatal("unexpected change or command boundary")
			}
			if mode == "append" && p.Changes()[0].Kind != plan.AppendMembers {
				t.Fatal("append selection changed")
			}
			if mode == "create" && p.Changes()[0].Kind != plan.CreateRule {
				t.Fatal("create selection changed")
			}
			if mode == "preserve" && p.Changes()[0].Kind != plan.RemoveRule {
				t.Fatal("preservation change lost")
			}
			report := operations.BatchReport{Version: 1, Devices: []operations.DevicePlan{{Device: p.Before().Metadata().Device, Batch: plan.BatchResult{Plan: p}}}}
			document := report.Document()
			got := document.Devices[0].Plan
			if got == nil || got.Digest != p.Digest() || got.Proof != proof || got.Cost != p.Cost() || !reflect.DeepEqual(got.Changes, p.Changes()) || !reflect.DeepEqual(got.Commands, p.Commands()) {
				t.Fatal("review lost approval fields")
			}
			if len(got.Targets) != len(p.Targets()) || len(got.InputRequests) != len(p.InputRequests()) {
				t.Fatal("review lost request provenance")
			}
			native := strings.HasPrefix(mode, "native")
			if (got.NativeOptions != nil) != native || (got.NativeChanges != nil) != native {
				t.Fatal("wrong native report family")
			}
			if strings.HasPrefix(mode, "batch") && (len(p.InputRequests()) != 2 || len(p.Targets()) != 1 || p.BatchOptions().MaxCandidates != 17) {
				t.Fatal("batch accepted/input distinction lost")
			}
			if mode == "native-partial" && (len(p.NativeInputs()) != 2 || len(p.Targets()) != 1) {
				t.Fatal("native accepted/input distinction lost")
			}
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			var restored operations.ReportDocument
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal("review semantic roundtrip", err)
			}
			again, err := json.Marshal(restored)
			if err != nil || !bytes.Equal(again, raw) {
				t.Fatal("review wire meaning changed", err)
			}
		})
	}
}

func intentFixture(t *testing.T, mode string) *plan.Plan {
	t.Helper()
	fw := baseline(t)
	planner := plan.Planner{Renderer: renderer{}, NativeRenderer: nativeRenderer{}, MaxCandidates: 17}
	q := request(t, "192.0.2.2/32")
	var p *plan.Plan
	var err error
	switch mode {
	case "reuse", "append", "create":
		if mode == "reuse" {
			q = request(t, "192.0.2.1/32")
		}
		if mode == "create" {
			planner.Renderer = renderer{rejectAppend: true}
		}
		p, err = planner.Plan(t.Context(), fw, []policy.Request{q})
	case "batch", "batch-covered":
		if mode == "batch-covered" {
			q = request(t, "192.0.2.1/32")
		}
		q.At = time.Date(2026, 11, 1, 8, 0, 0, 0, time.FixedZone("offset", 8*3600))
		result, e := planner.PlanBatch(t.Context(), fw, []policy.Request{{}, q})
		p, err = result.Plan, e
	case "native", "native-partial":
		inputs := []plan.NativeRequest{nativeInput(t)}
		inputs[0].Sources = []string{"ticket-42", "row-1"}
		if mode == "native-partial" {
			bad := nativeInput(t)
			bad.NAT[0].Steps[0].ID = "absent"
			inputs = append([]plan.NativeRequest{bad}, inputs...)
		}
		result, e := planner.PlanNativeBatch(t.Context(), fw, inputs)
		p, err = result.Plan, e
	case "preserve", "preserve-unchanged":
		d := fw.Export()
		d.Rules[0].Disabled = true
		fw, err = fm.Seal(d)
		if err != nil {
			t.Fatal(err)
		}
		after := fw
		var changes []plan.Change
		if mode == "preserve" {
			d.Rules = nil
			after, err = fm.Seal(d)
			if err != nil {
				t.Fatal(err)
			}
			changes = []plan.Change{{Kind: plan.RemoveRule, Rule: "10"}}
		}
		p, err = planner.Preserve(t.Context(), fw, after, changes, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	case "transfer":
		p, err = planner.Transfer(t.Context(), fw, []plan.RuleIntent{{Request: q, Action: fm.Drop, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant}}, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	default:
		t.Fatal(mode)
	}
	if err != nil || p == nil {
		t.Fatalf("%s: %v", mode, err)
	}
	return p
}
