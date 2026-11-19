package design_test

import (
	"slices"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
)

// TestPlan_OverridePlacesBeforeApplicationDeny: a deny rule matching an
// application (SSH) comes before the port deny that decides tcp/22. An
// override must place the permit before both, or SSH stays blocked.
func TestPlan_OverridePlacesBeforeApplicationDeny(t *testing.T) {
	t.Parallel()
	anyAddr := []firemon.AddressRef{inline("0.0.0.0/0")}
	app := rule("12", firemon.ActionDeny, "trust", "dmz", anyAddr, anyAddr, "tcp/22")
	app.Applications = []string{"SSH"}
	cfg := lab(
		rule("1", firemon.ActionPermit, "trust", "dmz", []firemon.AddressRef{inline("10.0.9.0/24")}, anyAddr, "HTTPS"),
		app,
		rule("78", firemon.ActionDeny, "trust", "dmz", anyAddr, anyAddr, "tcp/22"),
	)
	cfg.Services = append(cfg.Services, firemon.Service{Name: "tcp/22", Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(22))}})
	in := intent(t, "10.0.1.5", "172.16.0.10", "tcp/22")
	in.Override = true
	p := plan(t, cfg, in)
	if !p.Verified || p.Status != design.StatusChange {
		t.Fatalf("status %v verified %v (%s) unknown %v", p.Status, p.Verified, p.VerifyError, p.Unknown)
	}
	var before string
	for _, c := range p.Changes {
		if a, ok := c.(design.AddRule); ok {
			before = a.Before
		}
	}
	if before != "12" {
		t.Errorf("new rule placed before %q, want 12", before)
	}
	if !slices.Equal(p.Bypassed, []string{"12", "78"}) {
		t.Errorf("bypassed %v, want [12 78]", p.Bypassed)
	}
}
