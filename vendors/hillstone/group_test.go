package hillstone_test

import (
	"testing"
	"time"

	"github.com/gatework/firemon/vendors/hillstone"
)

func TestParse_RuleGroupHeaderBlocks(t *testing.T) {
	t.Parallel()
	cfg := mustParse(t, hillstone.Options{}, `rule id 100
  aggregate-type
  name "web"
exit
rule id 1
  action permit
  src-zone "trust"
  dst-zone "untrust"
  src-addr "Any"
  dst-addr "Any"
  service "Any"
  aggregate-rule 100
exit
rule id 100
  name "web-renamed"
exit
`)
	if len(cfg.Rules) != 1 || cfg.Rules[0].ID != "1" {
		t.Fatalf("a later block of a group header became a rule: %+v", cfg.Rules)
	}
	if len(cfg.RuleGroups) != 1 || cfg.RuleGroups[0].Name != "web-renamed" {
		t.Fatalf("groups = %+v", cfg.RuleGroups)
	}
	cfg = mustParse(t, hillstone.Options{}, `rule id 100
  aggregate-type
exit
rule id 1
  action permit
  src-zone "trust"
  dst-zone "untrust"
  src-addr "Any"
  dst-addr "Any"
  service "Any"
  aggregate-rule 100
exit
no rule id 100
`)
	if len(cfg.RuleGroups) != 0 || len(cfg.Rules) != 1 || cfg.Rules[0].Group != "" {
		t.Fatalf("no rule id on a group: groups %+v rules %+v", cfg.RuleGroups, cfg.Rules)
	}
}

func TestParseHits_IgnoresOtherIDs(t *testing.T) {
	t.Parallel()
	out := `rule id 13
  vsys id 0
  schedule id 4
  hit-count: 9
`
	s, err := hillstone.ParseHits(out, "fw1", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := s.Counter("13"); !ok || c.Hits != 9 || len(s.Counters) != 1 {
		t.Fatalf("counters = %+v", s.Counters)
	}
}
