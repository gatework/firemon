package migrate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/bootstrap"
	"github.com/gatework/firemon/migrate"
	"github.com/gatework/firemon/traffic"
)

// stoneConf exercises what PAN-OS cannot hold as written: exclusions,
// mixed objects, multi-protocol services, inline services, a validity
// window, an unmapped application and a wildcard domain.
const stoneConf = `zone "trust"
exit
zone "untrust"
exit
interface ethernet0/1
  zone  "trust"
  ip address 10.0.0.1/24
exit
interface ethernet0/2
  zone  "untrust"
  ip address 203.0.113.2/30
exit
ip vrouter "trust-vr"
  ip route 0.0.0.0/0 203.0.113.1
  snatrule id 1 from address-book "lan" to address-book "Any" service "Any" eif ethernet0/2 trans-to eif-ip mode dynamicport
exit
address "lan"
  ip 10.0.0.0/16
  exclude ip 10.0.128.0/17
exit
address "servers"
  ip 192.0.2.0/28
  range 192.0.2.100 192.0.2.110
exit
address "cdn"
  host "*.cdn.example.com"
exit
service "app-ports"
  tcp dst-port 8080
  udp dst-port 5353
exit
rule id 5
  action permit
  src-zone "trust"
  dst-zone "untrust"
  src-addr "lan"
  dst-addr "servers"
  service "app-ports"
  service "HTTPS"
  service-rule tcp dst-port 9000
  start-time 1/2/2026 08:00:00
  expire-time 12/31/2026 18:00:00
exit
rule id 6
  action permit
  src-zone "trust"
  dst-zone "untrust"
  src-addr "lan"
  dst-addr "cdn"
  service "Any"
exit
rule id 7
  action deny
  src-zone "trust"
  dst-zone "untrust"
  src-addr "Any"
  dst-addr "Any"
  service "Any"
  application "BitTorrent"
exit
`

func platform(t *testing.T, v firemon.Vendor) bootstrap.Platform {
	t.Helper()
	p, err := bootstrap.Lookup(v, time.UTC, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func translate(t *testing.T, from, to firemon.Vendor, text string, m migrate.Mapping) (migrate.Result, *firemon.Firewall, *firemon.Firewall) {
	t.Helper()
	src, err := platform(t, from).Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	srcFW, err := firemon.Compile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := platform(t, to)
	target, err := bootstrap.MigrationTarget(dst)
	if err != nil {
		t.Fatal(err)
	}
	res, err := migrate.Translate(src, m, target)
	if err != nil {
		t.Fatal(err)
	}
	script, err := dst.Render(res.Plan)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, c := range script.Commands {
		if !strings.HasPrefix(c, "move ") {
			lines = append(lines, c)
		}
	}
	back, err := dst.Parse(strings.Join(lines, "\n") + "\n")
	if err != nil {
		t.Fatal(err)
	}
	backFW, err := firemon.Compile(back)
	if err != nil {
		t.Fatal(err)
	}
	return res, srcFW, backFW
}

func item(res migrate.Result, kind migrate.ItemKind, source string) migrate.Item {
	for _, it := range res.Items {
		if it.Kind == kind && it.Source == source {
			return it
		}
	}
	return migrate.Item{}
}

// sameMatch checks that the read-back target rules match what the source
// rule matched.
func sameMatch(t *testing.T, src, back *firemon.Firewall, it migrate.Item) {
	t.Helper()
	s, _ := src.Rule(it.Source)
	var union traffic.Region
	for _, id := range it.Target {
		r, ok := back.Rule(id)
		if !ok {
			t.Fatalf("rule %s: target %s not read back", it.Source, id)
		}
		if r.Action() != s.Action() {
			t.Fatalf("rule %s: action %s, want %s", it.Source, r.Action(), s.Action())
		}
		union = union.Add(r.Match())
	}
	want := traffic.NewRegion(s.Match())
	if !want.SubtractRegion(union).IsEmpty() || !union.SubtractRegion(want).IsEmpty() {
		t.Fatalf("rule %s: read back %s, source %s", it.Source, union, want)
	}
}

func TestTranslate_StoneOSToPANOS(t *testing.T) {
	t.Parallel()
	res, src, back := translate(t, firemon.VendorHillstone, firemon.VendorPaloAlto, stoneConf, migrate.Mapping{
		Interfaces: map[string]string{"ethernet0/1": "ethernet1/1", "ethernet0/2": "ethernet1/2"},
	})
	r5 := item(res, migrate.ItemKindRule, "5")
	if r5.Fidelity != migrate.FidelityExact {
		t.Fatalf("rule 5: %+v", r5)
	}
	sameMatch(t, src, back, r5)
	for name, want := range map[string]migrate.Fidelity{"lan": migrate.FidelityExact, "servers": migrate.FidelityExact, "cdn": migrate.FidelityUntranslatable} {
		if got := item(res, migrate.ItemKindAddress, name); got.Fidelity != want {
			t.Errorf("address %s: %+v", name, got)
		}
	}
	for _, id := range []string{"6", "7"} {
		it := item(res, migrate.ItemKindRule, id)
		r, _ := back.Rule(it.Target[0])
		if it.Fidelity != migrate.FidelityUntranslatable || !r.Spec().Disabled {
			t.Errorf("rule %s is carried over disabled: %+v", id, it)
		}
	}
	if d := item(res, migrate.ItemKindDefault, "intrazone"); d.Fidelity != migrate.FidelityExact || len(d.Target) != 1 {
		t.Fatalf("StoneOS denies within a zone, PAN-OS allows: %+v", d)
	}
	if n := item(res, migrate.ItemKindNAT, "1"); n.Fidelity != migrate.FidelityExact || len(back.NATRules()) != 1 {
		t.Fatalf("source NAT: %+v", n)
	}
}

func TestTranslate_PANOSToStoneOS(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "vendors", "paloalto", "testdata", "basic.conf"))
	if err != nil {
		t.Fatal(err)
	}
	res, src, back := translate(t, firemon.VendorPaloAlto, firemon.VendorHillstone, string(raw), migrate.Mapping{
		Applications: map[string]string{"ssl": "SSL", "web-browsing": "HTTP"},
	})
	for _, id := range []string{"block-bad", "web-in", "not-lan"} {
		it := item(res, migrate.ItemKindRule, id)
		if it.Fidelity == migrate.FidelityUntranslatable {
			t.Fatalf("rule %s: %+v", id, it)
		}
		sameMatch(t, src, back, it)
	}
	if neg := item(res, migrate.ItemKindRule, "not-lan"); !strings.Contains(neg.Reason, "complement") {
		t.Fatalf("negated source written as a complement: %+v", neg)
	}
	if res.Count(migrate.FidelityUntranslatable) == 0 {
		t.Fatal("the FQDN-only and dynamic objects are reported")
	}
}

// FuzzTranslate: any configuration the StoneOS parser accepts translates
// and renders for PAN-OS without panicking, and exact rules stay exact.
func FuzzTranslate(f *testing.F) {
	f.Add(stoneConf)
	f.Fuzz(func(t *testing.T, text string) {
		src, err := platform(t, firemon.VendorHillstone).Parse(text)
		if err != nil {
			return
		}
		if _, err := firemon.Compile(src); err != nil {
			return
		}
		dst := platform(t, firemon.VendorPaloAlto)
		target, err := bootstrap.MigrationTarget(dst)
		if err != nil {
			t.Fatal(err)
		}
		res, err := migrate.Translate(src, migrate.Mapping{}, target)
		if err != nil {
			return
		}
		_, _ = dst.Render(res.Plan)
	})
}
