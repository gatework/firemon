package plan_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
)

// These observations were captured on the frozen pre-intent-refactor tree.
// They protect approval bytes indirectly through the digest, and every public
// report field directly, including absent versus empty mode-specific values.
func TestIntentCompatibility(t *testing.T) {
	for _, mode := range []string{"reuse", "append", "create", "batch", "batch-covered", "native", "native-partial", "preserve", "preserve-unchanged", "transfer"} {
		t.Run(mode, func(t *testing.T) {
			p := compatibilityPlan(t, mode)
			readback, err := p.Verify(t.Context(), p.After())
			if err != nil {
				t.Fatal(err)
			}
			if err := p.VerifyBaseline(t.Context(), p.Before()); err != nil {
				t.Fatal(err)
			}
			proof, preserved := p.Preservation()
			report := operations.BatchReport{Version: 1, Devices: []operations.DevicePlan{{Device: p.Before().Metadata().Device, Batch: plan.BatchResult{Plan: p}}}}
			observation := struct {
				Before, After string
				Report        operations.ReportDocument
				Options       plan.BatchOptions
				Preserved     bool
				Preservation  policy.Equivalence
				Readback      plan.Readback
			}{p.Before().SemanticDigest(), p.After().SemanticDigest(), report.Document(), p.BatchOptions(), preserved, proof, readback}
			raw, err := json.MarshalIndent(observation, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			assertIntentGolden(t, mode+".json", append(raw, '\n'))
		})
	}
}

func compatibilityPlan(t *testing.T, mode string) *plan.Plan {
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

func assertIntentGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "intent-compat", name)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("intent compatibility changed: %s", name)
	}
}
