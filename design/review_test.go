package design_test

import (
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
)

// Regression tests for the second review round (D1-D6).

func TestD1_ServiceSpecificDenyIsAConflict(t *testing.T) {
	t.Parallel()
	smb := rule("1", firemon.ActionDeny, "", "", nil, nil, "SMB")
	cfg := lab(smb)
	cfg.Services = append(cfg.Services, firemon.Service{Name: "SMB", Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(445))}})
	p := plan(t, cfg, intent(t, "10.0.1.9", "172.16.0.10", "tcp/445"))
	if p.Status != design.StatusConflict || len(p.Changes) != 0 {
		t.Fatalf("a deny for one service is deliberate: status %s changes %v", p.Status, describe(p.Changes))
	}
	zoned := rule("2", firemon.ActionDeny, "trust", "", nil, nil)
	p = plan(t, lab(zoned), intent(t, "10.0.1.9", "172.16.0.10", "tcp/445"))
	if p.Status != design.StatusConflict {
		t.Fatalf("a zone-scoped deny all is deliberate: %s", p.Status)
	}
}

func TestD2_NewRuleNamesAreUnique(t *testing.T) {
	t.Parallel()
	cfg := lab(rule("req", firemon.ActionPermit, "dmz", "trust", nil, nil))
	cfg.Semantics.NumericRuleIDs = false
	p := plan(t, cfg, intent(t, "10.0.2.5", "172.16.0.10", "tcp/443"))
	last := p.Changes[len(p.Changes)-1].(design.AddRule)
	if last.Rule.ID == "req" || last.Rule.Name == "req" {
		t.Fatalf("new rule reuses an existing name: %+v", last.Rule)
	}
}

func TestD3_ScheduledPermitDoesNotSatisfyPermanentAccess(t *testing.T) {
	t.Parallel()
	r := rule("5", firemon.ActionPermit, "trust", "dmz", nil, nil, "HTTPS")
	r.Schedule = "always-now"
	cfg := lab(r)
	cfg.Schedules = []firemon.Schedule{{Name: "always-now", Windows: []firemon.TimeWindow{{End: now.Add(time.Hour)}}}}
	p := plan(t, cfg, intent(t, "10.0.1.9", "172.16.0.10", "tcp/443"))
	if p.Status != design.StatusChange || !p.Verified {
		t.Fatalf("permanent access needs a permanent rule: %s verified=%v", p.Status, p.Verified)
	}
	in := intent(t, "10.0.2.9", "172.16.0.10", "tcp/22")
	in.Schedule = "always-now"
	p = plan(t, cfg, in)
	if !p.Verified {
		t.Fatalf("scheduled access verifies with the schedule active: %v", p.Unknown)
	}
}

func TestD4_UndecidableSpaceIsNotOpened(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.SecurityRule{ID: "1", Action: firemon.ActionDeny, Source: []firemon.AddressRef{firemon.NamedAddress("missing")}})
	p := plan(t, cfg, intent(t, "10.0.1.9", "172.16.0.10", "tcp/443"))
	if len(p.Changes) != 0 || len(p.Unknown) == 0 {
		t.Fatalf("a possible deny must not be bypassed: %v", describe(p.Changes))
	}
}

func TestD5_ExtensionPrefersOneExistingObject(t *testing.T) {
	t.Parallel()
	partial := rule("5", firemon.ActionPermit, "trust", "dmz", []firemon.AddressRef{inline("10.0.1.0/25")}, []firemon.AddressRef{firemon.NamedAddress("web")}, "HTTPS")
	p := plan(t, lab(partial), intent(t, "10.0.1.0/24", "172.16.0.10", "tcp/443"))
	got := strings.Join(describe(p.Changes), "; ")
	if got != "extend rule 5 source += ops" {
		t.Fatalf("want the existing /24 object, got %s", got)
	}
}

func TestD6_PortlessServicesNeedApplicationsOnPortOnlyVendors(t *testing.T) {
	t.Parallel()
	cfg := lab()
	cfg.Semantics.PortServicesOnly = true
	p := plan(t, cfg, intent(t, "10.0.1.9", "172.16.0.10", "icmp,tcp/22"))
	text := strings.Join(describe(p.Changes), "; ")
	if strings.Contains(text, "ICMP") || len(p.Unknown) == 0 || !p.Verified {
		t.Fatalf("icmp must be reported, tcp planned: %s %v", text, p.Unknown)
	}
}

func TestDuplicateRuleIDsAreIssues(t *testing.T) {
	t.Parallel()
	fw, err := firemon.Compile(lab(rule("1", firemon.ActionPermit, "", "", nil, nil), rule("1", firemon.ActionDeny, "", "", nil, nil)))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, i := range fw.Issues() {
		found = found || strings.Contains(i.Reason, "more than once")
	}
	if !found {
		t.Fatal("duplicate rule IDs must be reported")
	}
}
