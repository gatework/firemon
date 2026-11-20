package migrate_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/migrate"
	"github.com/gatework/firemon/traffic"
)

// denyConf has denies the target cannot name exactly: an application
// without a port (BitTorrent), a mapped one (SSH) and ICMP next to ports.
const denyConf = `zone "trust"
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
exit
rule id 1
  action deny
  src-zone "untrust"
  dst-zone "trust"
  src-addr "Any"
  dst-addr "Any"
  service "Any"
  application "SSH"
  application "SSH-PuTTY"
exit
rule id 2
  action deny
  src-zone "untrust"
  dst-zone "trust"
  src-addr "Any"
  dst-addr "Any"
  service "Any"
  application "BitTorrent"
exit
rule id 3
  action permit
  src-zone "trust"
  dst-zone "untrust"
  src-addr "Any"
  dst-addr "Any"
  service "ICMP"
  service "HTTPS"
exit
rule id 4
  action deny
  src-zone "trust"
  dst-zone "untrust"
  src-addr "Any"
  dst-addr "Any"
  service "Any"
  application "WeirdApp"
  application "HTTP"
exit
`

func TestTranslate_DenyNeverWeakened(t *testing.T) {
	t.Parallel()
	res, _, back := translate(t, firemon.VendorHillstone, firemon.VendorPaloAlto, denyConf, migrate.Mapping{
		Interfaces: map[string]string{"ethernet0/1": "ethernet1/1", "ethernet0/2": "ethernet1/2"},
	})
	// SSH maps by the built-in table: the deny stays, on applications.
	r1 := item(res, migrate.ItemKindRule, "1")
	if r1.Fidelity != migrate.FidelityApproximate {
		t.Fatalf("rule 1: %+v", r1)
	}
	if r, _ := back.Rule(r1.Target[0]); r.Spec().Disabled || !slices.Equal(r.Spec().Applications(), []string{"ssh"}) {
		t.Fatalf("rule 1 read back %+v", r.Spec())
	}
	// BitTorrent has no mapping and no known ports: lost, and said so.
	if !slices.Equal(res.DisabledDenies, []string{"2", "4"}) {
		t.Fatalf("disabled denies %v, want [2 4]", res.DisabledDenies)
	}
	// WeirdApp has no mapping: the deny is kept on the applications'
	// ports when all are known, else lost; HTTP alone is not enough.
	if r4 := item(res, migrate.ItemKindRule, "4"); r4.Fidelity != migrate.FidelityUntranslatable {
		t.Fatalf("rule 4: %+v", r4)
	}
	// ICMP becomes a companion rule matching the icmp application.
	r3 := item(res, migrate.ItemKindRule, "3")
	if r3.Fidelity == migrate.FidelityUntranslatable || len(r3.Target) != 2 {
		t.Fatalf("rule 3: %+v", r3)
	}
	app, _ := back.Rule(r3.Target[1])
	if !slices.Equal(app.Spec().Applications(), []string{"icmp"}) || app.Spec().Disabled {
		t.Fatalf("rule 3 companion %+v", app.Spec())
	}
}

func TestTranslate_DenyKeptOnApplicationPorts(t *testing.T) {
	t.Parallel()
	// commvault has no PAN-OS name in the table but known ports: the deny
	// stays in force on them.
	conf := strings.Replace(denyConf, `application "BitTorrent"`, `application "commvault"`, 1)
	res, _, back := translate(t, firemon.VendorHillstone, firemon.VendorPaloAlto, conf, migrate.Mapping{
		Interfaces: map[string]string{"ethernet0/1": "ethernet1/1", "ethernet0/2": "ethernet1/2"},
	})
	it := item(res, migrate.ItemKindRule, "2")
	if it.Fidelity != migrate.FidelityApproximate || slices.Contains(res.DisabledDenies, "2") {
		t.Fatalf("rule 2: %+v (disabled denies %v)", it, res.DisabledDenies)
	}
	r, _ := back.Rule(it.Target[0])
	want, _ := traffic.ParseServiceSet("tcp/8400-8403")
	if r.Spec().Disabled || len(r.Spec().Applications()) > 0 || !r.Match().Service.Equal(want) {
		t.Fatalf("rule 2 read back %+v, service %s", r.Spec(), r.Match().Service)
	}
}
