package converge_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/converge"
)

func TestDuplicateObjects(t *testing.T) {
	t.Parallel()
	host := func(name, a string) firemon.Address {
		return firemon.Address{Name: name, Entries: []firemon.AddressEntry{firemon.HostEntry(netip.MustParseAddr(a))}}
	}
	cfg := &firemon.Config{
		Vendor:    firemon.VendorHillstone,
		Addresses: []firemon.Address{host("web", "192.0.2.10"), host("Host_192.0.2.10", "192.0.2.10"), host("db", "192.0.2.20")},
		Rules: []firemon.SecurityRule{
			{ID: "1", Action: firemon.ActionPermit, Destination: []firemon.AddressRef{firemon.NamedAddress("web")}},
			{ID: "2", Action: firemon.ActionPermit, Destination: []firemon.AddressRef{firemon.NamedAddress("Host_192.0.2.10"), firemon.NamedAddress("db")}},
		},
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rep := converge.Analyze(fw, converge.Options{Now: func() time.Time { return time.Unix(0, 0) }})
	if rep.Count(converge.CategoryDuplicateObject) != 1 {
		t.Fatalf("web and Host_192.0.2.10 hold the same host: %+v", rep.Findings)
	}
	i := slices.IndexFunc(rep.Findings, func(f converge.Finding) bool { return f.Category == converge.CategoryDuplicateObject })
	f := rep.Findings[i]
	if f.Tier != converge.TierReview || len(f.Objects) != 2 {
		t.Fatalf("finding %+v", f)
	}
}

// A rule with criteria the model does not hold cannot be restored by a
// rollback, so deleting it is for review even when it is disabled.
func TestAnalyze_UnrestorableRuleIsReview(t *testing.T) {
	t.Parallel()
	cfg := &firemon.Config{
		Vendor: firemon.VendorHillstone,
		Rules: []firemon.SecurityRule{
			{ID: "1", Action: firemon.ActionPermit, Disabled: true, Unsupported: []string{"user alice"}},
			{ID: "2", Action: firemon.ActionPermit, Disabled: true},
		},
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rep := converge.Analyze(fw, converge.Options{Now: func() time.Time { return time.Unix(0, 0) }})
	for id, want := range map[string]converge.Tier{"1": converge.TierReview, "2": converge.TierSafe} {
		f, ok := rep.Find("disabled:" + id)
		if !ok || f.Tier != want {
			t.Errorf("rule %s: %+v, want tier %s", id, f, want)
		}
	}
}
