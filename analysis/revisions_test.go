package analysis_test

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/policy"
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
