package analysis_test

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"runtime"
	"testing"
	"time"
)

func TestRevisionComparisonSeparatesTextDeclarationsOrderAndProof(t *testing.T) {
	before := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}})
	d := before.Export()
	d.Raw = "# comment\n"
	d.Metadata.SourceDigest = ""
	after, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	cmp := analysis.RevisionComparer{}
	r, err := cmp.Compare(context.Background(), before, after, time.Time{})
	if err != nil || !r.TextChanged || len(r.Declarations) != 0 || r.RuleOrderChanged || r.NATChanged || r.Behavior != "equivalent" {
		t.Fatal(r, err)
	}
	d.Rules[0].Position = 5
	after, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	r, err = cmp.Compare(context.Background(), before, after, time.Time{})
	if err != nil || !r.RuleOrderChanged || len(r.Declarations) != 0 || r.Behavior != "equivalent" {
		t.Fatal(r, err)
	}
	d.Rules[1].Action = fm.Deny
	after, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	r, err = cmp.Compare(context.Background(), before, after, time.Time{})
	if err != nil || len(r.Declarations) != 1 || r.Behavior != "unproven" || r.Proof != nil {
		t.Fatal(r, err)
	}
	d.Diagnostics = []fm.Diagnostic{{Code: "unknown"}}
	after, err = fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	r, err = cmp.Compare(context.Background(), before, after, time.Time{})
	if err != nil || r.Behavior != "unproven" || r.AfterComplete {
		t.Fatal(r, err)
	}
	cmp.Engine.Limits.MaxVisits = 1
	if _, err = cmp.Compare(context.Background(), before, after, time.Time{}); !errors.Is(err, policy.ErrBudget) {
		t.Fatal(err)
	}
}

func TestRevisionComparisonReportsNATDriftWithoutClaimingBehavior(t *testing.T) {
	before := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}})
	d := before.Export()
	d.StaticNATs = []fm.StaticNATRecord{{Object: fm.Object{ID: "static"}, Match: d.Rules[0].Match, Source: []fm.Mapping{{Original: d.Addresses[0].Ranges[0], Translated: d.Addresses[1].Ranges[0], Mode: fm.Offset}}}}
	after, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	r, err := (analysis.RevisionComparer{}).Compare(context.Background(), before, after, time.Time{})
	if err != nil || !r.NATChanged || r.Behavior != "unproven" || len(r.Declarations) != 1 || r.Declarations[0].Catalog != "static_nat" {
		t.Fatal(r, err)
	}
	d.Metadata.Device = "other"
	other, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (analysis.RevisionComparer{}).Compare(context.Background(), before, other, time.Time{}); !errors.Is(err, analysis.ErrInvalid) {
		t.Fatal("compared unrelated devices", err)
	}
}

func TestRevisionComparisonBudgetsNestedDeclarationsBeforeCopying(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}}).Export()
	r := d.Addresses[0].Ranges[0]
	d.Addresses[0].Ranges = make([]flow.AddressRange, 2048)
	for i := range d.Addresses[0].Ranges {
		d.Addresses[0].Ranges[i] = r
	}
	fw, err := fm.Seal(d)
	if err != nil || !fw.Complete() {
		t.Fatalf("fixture: %v", err)
	}
	comparer := analysis.RevisionComparer{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 32}}}
	var start, end runtime.MemStats
	runtime.ReadMemStats(&start)
	_, err = comparer.Compare(t.Context(), fw, fw, time.Time{})
	runtime.ReadMemStats(&end)
	if !errors.Is(err, policy.ErrBudget) {
		t.Errorf("nested declarations escaped budget: %v", err)
	}
	if allocated := end.TotalAlloc - start.TotalAlloc; allocated > 64<<10 {
		t.Errorf("nested declarations copied before rejection: %d bytes", allocated)
	}
	comparer.Engine.Limits.MaxVisits = 100000
	result, err := comparer.Compare(t.Context(), fw, fw, time.Time{})
	if err != nil || result.Behavior != "equivalent" {
		t.Fatalf("adequate nested declaration budget: %+v, %v", result, err)
	}
}
