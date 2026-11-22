package hillstone_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
	"github.com/gatework/firemon/vendors/hillstone"
)

var natNow = func() time.Time { return time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC) }

func natIntent(t *testing.T, src, dst, svc string, nat design.NATIntent) design.Intent {
	t.Helper()
	in := design.Intent{Name: "req7", NAT: &nat}
	var err1, err2, err3 error
	in.Src, err1 = traffic.ParseAddressSet(src)
	in.Dst, err2 = traffic.ParseAddressSet(dst)
	in.Service, err3 = traffic.ParseServiceSet(svc)
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatal(err1, err2, err3)
	}
	return in
}

func natPlan(t *testing.T, conf string, in design.Intent) (*design.Plan, design.Script) {
	t.Helper()
	fw := compileText(t, conf)
	p, err := design.New(fw, design.Options{Now: natNow}).Plan(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.NAT == nil {
		t.Fatal("no NAT outcome")
	}
	script, err := hillstone.Renderer{}.Render(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, script
}

// readBack parses the configuration with the rendered commands appended,
// as the device would list it, and queries req.
func readBack(t *testing.T, conf string, script design.Script, req query.Request) *query.Result {
	t.Helper()
	fw := compileText(t, conf+strings.Join(script.Commands, "\n")+"\n")
	res, err := query.New(fw, query.Options{Now: natNow}).Query(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestNATDesign_SourceAlreadyTranslatedByCatchAll(t *testing.T) {
	t.Parallel()
	p, _ := natPlan(t, natOrderConf, natIntent(t, "10.0.7.0/24", "192.0.2.10", "tcp/443", design.NATIntent{Mode: design.NATModeSource}))
	if p.NAT.Status != design.NATStatusSatisfied || len(p.NAT.Existing) != 1 || p.NAT.Existing[0] != "1" {
		t.Fatalf("snatrule 1 (Any) already translates: %+v", p.NAT)
	}
}

func TestNATDesign_SourcePlacedBeforeTheRuleThatMatchesFirst(t *testing.T) {
	t.Parallel()
	in := natIntent(t, "10.0.7.0/24", "192.0.2.10", "tcp/443", design.NATIntent{Mode: design.NATModeSource, Address: netip.MustParseAddr("198.51.100.77")})
	p, script := natPlan(t, natOrderConf, in)
	if p.NAT.Status != design.NATStatusAdded || p.NAT.Rule != "10" || p.NAT.Before != "1" || !p.Verified {
		t.Fatalf("outcome %+v verified %v %s", p.NAT, p.Verified, p.VerifyError)
	}
	want := `  snatrule id 10 before 1 from address-book "Net_10.0.7.0_24" to address-book "Host_192.0.2.10" service "HTTPS" eif ethernet0/2 trans-to ip 198.51.100.77/32 mode dynamicport`
	if !strings.Contains(strings.Join(script.Commands, "\n"), want) {
		t.Fatalf("commands:\n%s", strings.Join(script.Commands, "\n"))
	}
	if !strings.Contains(strings.Join(script.Rollback, "\n"), "no snatrule id 10") {
		t.Fatalf("rollback %v", script.Rollback)
	}
	res := readBack(t, natOrderConf, script, query.Request{Src: in.Src, Dst: in.Dst, Service: in.Service})
	for _, path := range res.Paths {
		if len(path.SourceNAT) != 1 || path.SourceNAT[0].Rule.Spec().ID != "10" || path.SourceNAT[0].Translated.String() != "198.51.100.77" {
			t.Fatalf("after the change the new rule must match first: %+v", path.SourceNAT)
		}
	}
	// Other sources still meet the catch-all.
	rest := readBack(t, natOrderConf, script, query.Request{Src: host(t, "10.0.9.9"), Dst: in.Dst, Service: in.Service})
	if got := rest.Paths[0].SourceNAT; len(got) != 1 || got[0].Rule.Spec().ID != "1" {
		t.Fatalf("outside the intent snatrule 1 still applies: %+v", got)
	}
}

func TestNATDesign_DestinationWithPortAndAccess(t *testing.T) {
	t.Parallel()
	in := natIntent(t, "203.0.113.208", "10.0.5.20", "tcp/443", design.NATIntent{
		Mode: design.NATModeDestination, Address: netip.MustParseAddr("198.51.100.50"), Port: 8443,
	})
	p, script := natPlan(t, natOrderConf, in)
	if p.NAT.Status != design.NATStatusAdded || p.NAT.Rule != "1" || !p.Verified || p.Status != design.StatusChange {
		t.Fatalf("plan %s verified %v %s nat %+v unknown %v", p.Status, p.Verified, p.VerifyError, p.NAT, p.Unknown)
	}
	text := strings.Join(script.Commands, "\n")
	if !strings.Contains(text, `dnatrule id 1 from address-book "Any" to ip 198.51.100.50/32 service "TCP_8443" trans-to ip 10.0.5.20/32 port 443`) {
		t.Fatalf("commands:\n%s", text)
	}
	pub, _ := traffic.ParseServiceSet("tcp/8443")
	res := readBack(t, natOrderConf, script, query.Request{Src: in.Src, Dst: host(t, "198.51.100.50"), Service: pub})
	if res.Verdict != query.VerdictAllowed || len(res.Paths) != 1 || res.Paths[0].DestinationNAT == nil {
		t.Fatalf("published service must be translated and permitted: %s %+v", res.Verdict, res.Paths)
	}
}

func TestNATDesign_DestinationNeedsAnAddress(t *testing.T) {
	t.Parallel()
	p, _ := natPlan(t, natOrderConf, natIntent(t, "203.0.113.208", "10.0.5.20", "tcp/443", design.NATIntent{Mode: design.NATModeDestination}))
	if p.NAT.Status != design.NATStatusNeedsAddress || p.Status != design.StatusIndeterminate || len(p.Changes) != 0 {
		t.Fatalf("plan %+v", p.NAT)
	}
}

func TestNATDesign_Static(t *testing.T) {
	t.Parallel()
	in := natIntent(t, "203.0.113.208", "10.0.5.21", "tcp/22", design.NATIntent{Mode: design.NATModeStatic, Address: netip.MustParseAddr("198.51.100.51")})
	p, script := natPlan(t, natOrderConf, in)
	if p.NAT.Status != design.NATStatusAdded || !p.Verified {
		t.Fatalf("plan %s %s %+v", p.Status, p.VerifyError, p.NAT)
	}
	if !strings.Contains(strings.Join(script.Commands, "\n"), "bnatrule id 1 virtual ip 198.51.100.51/32 real ip 10.0.5.21/32") {
		t.Fatalf("commands %v", script.Commands)
	}
}

func host(t *testing.T, a string) traffic.AddressSet {
	t.Helper()
	s, err := traffic.ParseAddressSet(a)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestNATDesign_ReadbackMatchesPrediction checks what deployment checks:
// the device's configuration after the commands equals the baseline with
// the plan applied.
func TestNATDesign_ReadbackMatchesPrediction(t *testing.T) {
	t.Parallel()
	intents := []design.Intent{
		natIntent(t, "10.0.7.0/24", "192.0.2.10", "tcp/443", design.NATIntent{Mode: design.NATModeSource, Address: netip.MustParseAddr("198.51.100.77")}),
		natIntent(t, "10.0.8.0/24", "192.0.2.10", "tcp/443", design.NATIntent{Mode: design.NATModeSource, Interface: "ethernet0/2", Address: netip.Addr{}}),
		natIntent(t, "203.0.113.208", "10.0.5.20", "tcp/443", design.NATIntent{Mode: design.NATModeDestination, Address: netip.MustParseAddr("198.51.100.50"), Port: 8443}),
		natIntent(t, "203.0.113.208", "10.0.5.21", "tcp/22", design.NATIntent{Mode: design.NATModeStatic, Address: netip.MustParseAddr("198.51.100.51")}),
	}
	for _, in := range intents {
		p, script := natPlan(t, natOrderConf, in)
		if len(p.Changes) == 0 {
			continue
		}
		predicted := mustParse(t, hillstone.Options{}, natOrderConf)
		if err := design.Apply(predicted, p.Changes); err != nil {
			t.Fatal(err)
		}
		want := compileConfig(t, predicted)
		got := compileText(t, natOrderConf+strings.Join(script.Commands, "\n")+"\n")
		if want.Fingerprint() != got.Fingerprint() {
			t.Errorf("%s: readback differs from the prediction", in.NAT.Mode)
		}
	}
}
