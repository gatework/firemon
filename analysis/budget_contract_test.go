package analysis_test

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/paloalto"
)

func TestRiskBudgetsIncompleteRowsBeforeReturningUnknown(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.2", "198.51.100.1"}}).Export()
	d.Diagnostics = []fm.Diagnostic{{Code: "unknown", Message: "unparsed source"}}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	q := request(t, "192.0.2.1", "198.51.100.1")
	definition := analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Declared, Relation: analysis.Intersects, Traffic: q.Traffic}
	// Evidence is retained with every row, so its indexing and copies also
	// consume visits. A useful allowance returns unknown, never clean results.
	for _, limit := range []int{1, 32} {
		rows, err := (analysis.RiskAnalyzer{Engine: policy.Engine{Limits: policy.Limits{MaxVisits: limit}}}).Analyze(context.Background(), fw, q, definition)
		if limit == 1 {
			if rows != nil || !errors.Is(err, policy.ErrBudget) {
				t.Fatalf("partial over-budget findings: %v, %v", rows, err)
			}
		} else if err != nil || len(rows) != 2 || rows[0].Value != analysis.Unknown {
			t.Fatalf("bounded unknown rows: %v, %v", rows, err)
		}
	}
}

func TestConvergenceSharesVisitsAcrossCandidateProofPreparation(t *testing.T) {
	fw := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}})
	c := analysis.Converger{Planner: plan.Planner{Renderer: hillstone.Renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 8}}}}
	rows, err := c.Candidates(context.Background(), fw, time.Time{})
	if rows != nil || !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("candidate visits reset: %v, %v", rows, err)
	}
}

func TestMigrationAccumulatesMappingAndPartitionVisits(t *testing.T) {
	source, target := translationGraphs(t)
	m := analysis.Migrator{Planner: plan.Planner{Renderer: paloalto.Renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: 16}}}}
	p, err := m.Plan(context.Background(), source, target, analysis.MigrationRequest{Chains: map[fm.PolicyChain]fm.PolicyChain{{RuleSet: "security"}: {RuleSet: "security"}}, Zones: map[fm.ID]fm.ID{"inside": "trust", "outside": "untrust"}, Pairs: []analysis.ZonePair{{From: "inside", To: "outside"}}})
	if p != nil || !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("migration visits reset: %v, %v", p, err)
	}
}

func TestLifecyclePlansBudgetNestedCatalogBeforeCopying(t *testing.T) {
	d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}, {"192.0.2.1", "198.51.100.1"}}).Export()
	ranges := make([]flow.AddressRange, 2048)
	for i := range ranges {
		ranges[i] = d.Addresses[0].Ranges[0]
	}
	d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: "unused"}, Ranges: ranges})
	fw, err := fm.Seal(d)
	if err != nil || !fw.Complete() {
		t.Fatalf("fixture: %v", err)
	}
	for _, entry := range []string{"convergence", "reclamation"} {
		t.Run(entry, func(t *testing.T) {
			for _, limit := range []int{128, 100000} {
				planner := plan.Planner{Renderer: hillstone.Renderer{}, Engine: policy.Engine{Limits: policy.Limits{MaxVisits: limit}}}
				var start, end runtime.MemStats
				runtime.ReadMemStats(&start)
				var result *plan.Plan
				if entry == "convergence" {
					result, err = (analysis.Converger{Planner: planner}).Plan(t.Context(), fw, []fm.ID{"1", "2"}, time.Time{})
				} else {
					result, err = (analysis.Reclaimer{Planner: planner}).Plan(t.Context(), fw, analysis.ReclamationRequest{}, []fm.ID{"2"})
				}
				runtime.ReadMemStats(&end)
				if limit == 128 {
					if result != nil || !errors.Is(err, policy.ErrBudget) {
						t.Errorf("nested catalog escaped budget: plan=%v, err=%v", result != nil, err)
					}
					if allocated := end.TotalAlloc - start.TotalAlloc; allocated > 64<<10 {
						t.Errorf("nested catalog copied before rejection: %d bytes", allocated)
					}
				} else if err != nil || result == nil {
					t.Fatalf("adequate nested catalog budget: %v", err)
				}
			}
		})
	}
}

func TestLifecycleReportsBudgetNestedRuleCopies(t *testing.T) {
	for _, field := range []string{"sources", "spans"} {
		t.Run(field, func(t *testing.T) {
			d := graph(t, [][2]string{{"192.0.2.1", "198.51.100.1"}}).Export()
			const nested = 8192
			if field == "sources" {
				ref := d.Rules[0].Match.Sources[0]
				d.Rules[0].Match.Sources = make([]fm.AddressRef, nested)
				for i := range d.Rules[0].Match.Sources {
					d.Rules[0].Match.Sources[i] = ref
				}
			} else {
				d.Rules[0].Spans = make([]fm.Span, nested)
				for i := range d.Rules[0].Spans {
					d.Rules[0].Spans[i] = fm.Span{First: i + 1, Last: i + 1}
				}
			}
			q := request(t, "192.0.2.1", "198.51.100.1")
			definition := analysis.RiskDefinition{ID: "risk", Version: "1", Mode: analysis.Effective, Relation: analysis.Intersects, Traffic: q.Traffic}
			for _, entry := range []string{"convergence", "risk"} {
				t.Run(entry, func(t *testing.T) {
					data := d
					if entry == "risk" {
						// Returning unknown still retains source evidence and must bound
						// that work before copying the nested rule declaration.
						data.Diagnostics = []fm.Diagnostic{{Code: "unknown", Message: "unparsed source"}}
					}
					fw, err := fm.Seal(data)
					if err != nil {
						t.Fatal(err)
					}
					for _, allowance := range []struct {
						name   string
						visits int
					}{{"too-small", 32}, {"adequate", 100000}} {
						t.Run(allowance.name, func(t *testing.T) {
							engine := policy.Engine{Limits: policy.Limits{MaxVisits: allowance.visits}}
							var start, end runtime.MemStats
							runtime.ReadMemStats(&start)
							var partial bool
							var err error
							if entry == "convergence" {
								rows, callErr := (analysis.Converger{Planner: plan.Planner{Engine: engine}}).Candidates(t.Context(), fw, time.Time{})
								err, partial = callErr, rows != nil
								if allowance.name == "adequate" && len(rows) != 0 {
									t.Fatal("a single rule produced convergence candidates")
								}
							} else {
								rows, callErr := (analysis.RiskAnalyzer{Engine: engine}).Analyze(t.Context(), fw, q, definition)
								err, partial = callErr, rows != nil
								if allowance.name == "adequate" && (len(rows) != 1 || rows[0].Value != analysis.Unknown) {
									t.Fatal("incomplete rule evidence did not remain unknown")
								}
							}
							runtime.ReadMemStats(&end)
							if allowance.name == "too-small" {
								if partial || !errors.Is(err, policy.ErrBudget) {
									t.Errorf("nested rule escaped budget: partial=%v err=%v", partial, err)
								}
								if allocated := end.TotalAlloc - start.TotalAlloc; allocated > 64<<10 {
									t.Errorf("nested rule copied before rejection: %d bytes", allocated)
								}
							} else if err != nil {
								t.Fatalf("adequate declaration budget: %v", err)
							}
						})
					}
				})
			}
		})
	}
}
