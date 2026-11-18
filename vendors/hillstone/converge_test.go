package hillstone_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon/converge"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/hits"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
	"github.com/gatework/firemon/vendors/hillstone"
)

// convergeConf: rules 1 and 3 differ only in destination and nothing in
// between decides their traffic otherwise; rule 5 differs only in
// destination too, but deny 4 in between matches its traffic; rule 6
// repeats rule 1; rule 9 is a broad permit; the old-* objects are unused.
const convergeConf = `zone "inside"
exit
zone "outside"
exit
address "office"
  ip 10.1.0.0/24
exit
address "db1"
  ip 192.0.2.11/32
exit
address "db2"
  ip 192.0.2.12/32
exit
address "db5"
  ip 192.0.2.15/32
exit
address "old-host"
  ip 203.0.113.99/32
exit
address "old-group"
  member "old-host"
exit
rule id 1
  action permit
  src-zone "inside"
  dst-zone "outside"
  src-addr "office"
  dst-addr "db1"
  service "HTTPS"
exit
rule id 2
  action deny
  src-zone "inside"
  dst-zone "outside"
  src-addr "Any"
  dst-addr "db1"
  service "SSH"
exit
rule id 3
  action permit
  src-zone "inside"
  dst-zone "outside"
  src-addr "office"
  dst-addr "db2"
  service "HTTPS"
exit
rule id 4
  action deny
  src-zone "inside"
  dst-zone "outside"
  src-addr "Any"
  dst-addr "db5"
  service "Any"
exit
rule id 5
  action permit
  src-zone "inside"
  dst-zone "outside"
  src-addr "office"
  dst-addr "db5"
  service "HTTPS"
exit
rule id 6
  action permit
  src-zone "inside"
  dst-zone "outside"
  src-addr "office"
  dst-addr "db1"
  service "HTTPS"
exit
rule id 9
  action permit
  src-zone "inside"
  dst-zone "outside"
  src-addr "Any"
  dst-addr "Any"
  service "Any"
exit
`

var convergeNow = func() time.Time { return time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC) }

func TestConverge_FindsAndPlansSafeCleanups(t *testing.T) {
	t.Parallel()
	fw := compileText(t, convergeConf)
	counters := &hits.Snapshot{Taken: convergeNow(), Since: convergeNow().Add(-90 * 24 * time.Hour), Counters: []hits.Counter{{Rule: "9"}}}
	rep := converge.Analyze(fw, converge.Options{Now: convergeNow, Hits: counters})
	merge, ok := rep.Find("mergeable:1")
	if !ok || !slices.Equal(merge.Merge.Remove, []string{"3"}) || merge.Merge.Field != design.FieldDestination {
		t.Fatalf("rules 1 and 3 merge on destination; rule 5 crosses deny 4: %+v", rep.Findings)
	}
	if _, ok := rep.Find("redundant:6"); !ok {
		t.Fatal("rule 6 repeats rule 1")
	}
	b, ok := rep.Find("broad:9")
	if !ok || b.Evidence != converge.EvidenceBoth || !slices.Contains(b.Reasons, converge.ReasonNoHits) {
		t.Fatalf("rule 9 is broad and unused: %+v", b)
	}
	if rep.Count(converge.CategoryUnusedObject) != 2 {
		t.Fatalf("old-group then old-host: %+v", rep.Findings)
	}

	plan, err := converge.Plan(fw, rep, converge.Selection{}, converge.PlanOptions{Now: convergeNow})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Verified || plan.Kind != design.PlanKindCleanup {
		t.Fatalf("plan %s verified %v: %s", plan.Kind, plan.Verified, plan.VerifyError)
	}
	script, err := hillstone.Renderer{}.Render(plan)
	if err != nil {
		t.Fatal(err)
	}
	// What the device reads back after the commands equals the prediction.
	predicted := mustParse(t, hillstone.Options{}, convergeConf)
	if err := design.Apply(predicted, plan.Changes); err != nil {
		t.Fatal(err)
	}
	got := compileText(t, convergeConf+strings.Join(script.Commands, "\n")+"\n")
	if got.Fingerprint() != compileConfig(t, predicted).Fingerprint() {
		t.Fatalf("readback differs from the prediction:\n%s", strings.Join(script.Commands, "\n"))
	}
	// And the decisions are those of before.
	src, _ := traffic.ParseAddressSet("10.1.0.5")
	dst, _ := traffic.ParseAddressSet("192.0.2.12")
	svc, _ := traffic.ParseServiceSet("tcp/443")
	res, err := query.New(got, query.Options{Now: convergeNow}).Query(query.Request{Src: src, Dst: dst, Service: svc, FromZone: "inside", ToZone: "outside"})
	if err != nil || res.Verdict != query.VerdictAllowed || res.Paths[0].Decisions[0].Rule.ID() != "1" {
		t.Fatalf("db2 is now permitted by the merged rule 1: %+v %v", res, err)
	}
	// Rolling back restores the original configuration.
	back := compileText(t, convergeConf+strings.Join(script.Commands, "\n")+"\n"+strings.Join(script.Rollback, "\n")+"\n")
	if back.Fingerprint() != fw.Fingerprint() {
		t.Fatalf("rollback does not restore the configuration:\n%s", strings.Join(script.Rollback, "\n"))
	}
}

func TestConverge_VerifierRejectsAMergeAcrossADeny(t *testing.T) {
	t.Parallel()
	fw := compileText(t, convergeConf)
	rep := converge.Report{Findings: []converge.Finding{{
		ID: "forced", Category: converge.CategoryMergeable, Tier: converge.TierSafe,
		Merge: &converge.Merge{Keep: "1", Remove: []string{"5"}, Field: design.FieldDestination},
	}}}
	plan, err := converge.Plan(fw, rep, converge.Selection{}, converge.PlanOptions{Now: convergeNow})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Verified || !strings.Contains(plan.VerifyError, "effective policy") {
		t.Fatalf("moving rule 5 above deny 4 opens db5: verified %v %q", plan.Verified, plan.VerifyError)
	}
}
