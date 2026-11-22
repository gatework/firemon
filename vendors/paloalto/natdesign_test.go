package paloalto_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
	"github.com/gatework/firemon/vendors/paloalto"
)

func natPlan(t *testing.T, src, dst, svc string, nat design.NATIntent) (string, *design.Plan, design.Script) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "basic.conf"))
	if err != nil {
		t.Fatal(err)
	}
	_, fw := compileSet(t, string(raw))
	in := design.Intent{Name: "req7", NAT: &nat}
	in.Src, _ = traffic.ParseAddressSet(src)
	in.Dst, _ = traffic.ParseAddressSet(dst)
	in.Service, _ = traffic.ParseServiceSet(svc)
	p, err := design.New(fw, design.Options{Now: func() time.Time { return time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC) }, Naming: paloalto.Naming()}).Plan(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.NAT == nil || p.NAT.Status != design.NATStatusAdded || !p.Verified {
		t.Fatalf("plan %s verified %v %s nat %+v unknown %v", p.Status, p.Verified, p.VerifyError, p.NAT, p.Unknown)
	}
	script, err := paloalto.Renderer{}.Render(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), p, script
}

// sameRule checks that the rendered commands read back as the planned rule;
// the move command sets the order, which a readback lists directly.
func sameRule(t *testing.T, base string, p *design.Plan, script design.Script) {
	t.Helper()
	var set []string
	for _, c := range script.Commands {
		if strings.HasPrefix(c, "set ") {
			set = append(set, c)
		}
	}
	got, _ := compileSet(t, base+strings.Join(set, "\n")+"\n")
	predicted, _ := compileSet(t, base)
	if err := design.Apply(predicted, p.Changes); err != nil {
		t.Fatal(err)
	}
	find := func(cfg *firemon.Config) firemon.DynamicNAT {
		i := slices.IndexFunc(cfg.DynamicNATs, func(n firemon.DynamicNAT) bool { return n.ID == p.NAT.Rule })
		if i < 0 {
			t.Fatalf("rule %s missing", p.NAT.Rule)
		}
		n := cfg.DynamicNATs[i]
		n.Precedence = 0
		return n
	}
	if g, w := find(got), find(predicted); !equalJSON(t, g, w) {
		t.Fatalf("readback\n%+v\nplanned\n%+v", g, w)
	}
}

func TestNATDesign_SourceBeforeInterfacePAT(t *testing.T) {
	t.Parallel()
	base, p, script := natPlan(t, "10.0.0.9", "203.0.113.208", "tcp/443", design.NATIntent{Mode: design.NATModeSource, Address: netip.MustParseAddr("198.51.100.200")})
	if p.NAT.Before != "snat-out" || p.NAT.Rule != "To_untrust_req7" {
		t.Fatalf("outcome %+v", p.NAT)
	}
	text := strings.Join(script.Commands, "\n")
	for _, want := range []string{
		"set rulebase nat rules To_untrust_req7 source-translation dynamic-ip-and-port translated-address 198.51.100.200/32",
		"move rulebase nat rules To_untrust_req7 before snat-out",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
	sameRule(t, base, p, script)
}

func TestNATDesign_DestinationAndPreNATSecurityRule(t *testing.T) {
	t.Parallel()
	base, p, script := natPlan(t, "203.0.113.208", "172.16.0.20", "tcp/443", design.NATIntent{
		Mode: design.NATModeDestination, Address: netip.MustParseAddr("198.51.100.81"), Port: 8443,
	})
	text := strings.Join(script.Commands, "\n")
	for _, want := range []string{
		"destination-translation translated-address 172.16.0.20/32",
		"destination-translation translated-port 443",
		"set rulebase security rules req7 to dmz",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
	sameRule(t, base, p, script)
}

func TestNATDesign_StaticBidirectionalBeforeGenericPAT(t *testing.T) {
	t.Parallel()
	base, p, script := natPlan(t, "203.0.113.208", "172.16.0.21", "tcp/22", design.NATIntent{Mode: design.NATModeStatic, Address: netip.MustParseAddr("198.51.100.82")})
	if p.NAT.Before != "snat-out" {
		t.Fatalf("the server's outbound half must match before the interface PAT: %+v", p.NAT)
	}
	if !strings.Contains(strings.Join(script.Commands, "\n"), "source-translation static-ip bi-directional yes") {
		t.Fatalf("commands %v", script.Commands)
	}
	sameRule(t, base, p, script)
}
