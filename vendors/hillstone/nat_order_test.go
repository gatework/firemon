package hillstone_test

import (
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
	"github.com/gatework/firemon/vendors/hillstone"
)

// natOrderConf mirrors a site edge: inside traffic leaves by the default
// route, a PBR policy bound to the inside zone sends some destinations to a
// second uplink, and ordered snatrules on that uplink translate it.
const natOrderConf = `zone "inside"
  vrouter "trust-vr"
  bind pbr-policy "inside-pbr"
exit
zone "outside"
exit
zone "inet"
exit
interface ethernet0/1
  zone  "inside"
  ip address 10.0.0.1 255.255.0.0
exit
interface ethernet0/2
  zone  "inet"
  ip address 198.51.100.2 255.255.255.0
exit
interface ethernet0/3
  zone  "outside"
  ip address 203.0.113.2 255.255.255.252
exit
address "video"
  ip 192.0.2.0/24
exit
address "vip-users"
  ip 10.0.5.0/24
exit
address "old-users"
  ip 10.0.6.0/24
exit
ip vrouter "trust-vr"
  snatrule id 9 from address-book "old-users" to address-book "Any" service "Any" eif ethernet0/2 trans-to ip 198.51.100.9 mode dynamicport disable 
  snatrule id 4 from address-book "vip-users" to address-book "Any" service "Any" eif ethernet0/2 trans-to ip 198.51.100.4 mode dynamicport 
  snatrule id 1 from address-book "Any" to address-book "Any" service "Any" eif ethernet0/2 trans-to ip 198.51.100.1 mode dynamicport 
  snatrule id 2 from address-book "vip-users" to address-book "Any" service "Any" eif ethernet0/2 trans-to ip 198.51.100.200 mode dynamicport 
  ip route 0.0.0.0/0 203.0.113.1
exit
pbr-policy "inside-pbr" vrouter "trust-vr"
  match id 3
    src-addr "Any"
    dst-addr "video"
    service "Any"
    nexthop 198.51.100.254
  exit
  match id 8
    src-addr "Any"
    dst-addr "Any"
    service "Any"
    nexthop 198.51.100.254
    user-group "AD" "staff"
  exit
exit
rule id 1
  action permit
  src-zone "inside"
  src-addr "Any"
  dst-addr "Any"
  service "Any"
exit
`

func natOrderEngine(t *testing.T) *query.Engine {
	t.Helper()
	cfg, err := hillstone.New(hillstone.Options{}).Parse(natOrderConf)
	if err != nil {
		t.Fatal(err)
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PolicyRoutes) != 2 || len(cfg.PolicyBindings) != 1 || len(fw.Issues()) != 1 {
		t.Fatalf("policy routes %+v bindings %+v issues %v", cfg.PolicyRoutes, cfg.PolicyBindings, fw.Issues())
	}
	return query.New(fw, query.Options{Now: func() time.Time { return time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC) }})
}

func ask(t *testing.T, e *query.Engine, src, dst string) *query.Result {
	t.Helper()
	s, _ := traffic.ParseAddressSet(src)
	d, _ := traffic.ParseAddressSet(dst)
	res, err := e.Query(query.Request{Src: s, Dst: d, Service: traffic.PortService(traffic.ProtocolTCP, traffic.Port(443))})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestNAT_FirstMatchInOrder(t *testing.T) {
	t.Parallel()
	e := natOrderEngine(t)
	tests := []struct {
		name, src   string
		rule        string
		position    int
		translated  string
		skippedRule string
	}{
		{"earlier specific rule wins", "10.0.5.7", "4", 1, "198.51.100.4", ""},
		{"later rule for the same source never applies", "10.0.5.8", "4", 1, "198.51.100.4", ""},
		{"disabled rule is skipped", "10.0.6.7", "1", 2, "198.51.100.1", "nat 9"},
		{"catch-all for the rest", "10.0.9.9", "1", 2, "198.51.100.1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := ask(t, e, tt.src, "192.0.2.10")
			if len(res.Paths) != 1 {
				t.Fatalf("paths %+v", res.Paths)
			}
			p := res.Paths[0]
			if p.PolicyRoute != "inside-pbr/3" || p.To != "inet" || len(p.SourceNAT) != 1 {
				t.Fatalf("path %+v", p)
			}
			h := p.SourceNAT[0]
			if h.Rule.Spec().ID != tt.rule || h.Position != tt.position || h.Translated.String() != tt.translated {
				t.Fatalf("NAT %s at %d -> %s", h.Rule.Spec().ID, h.Position, h.Translated)
			}
			if tt.skippedRule != "" && (len(p.NATSkipped) != 1 || p.NATSkipped[0].String() != tt.skippedRule) {
				t.Fatalf("skipped %v", p.NATSkipped)
			}
		})
	}
}

func TestPBR_UndecidableEntryBranches(t *testing.T) {
	t.Parallel()
	res := ask(t, natOrderEngine(t), "10.0.9.9", "8.8.8.8")
	if len(res.Paths) != 2 {
		t.Fatalf("want a branch through the user-group route and one without: %+v", res.Paths)
	}
	var viaPBR, viaTable bool
	for _, p := range res.Paths {
		switch {
		case p.PolicyRoute == "inside-pbr/8" && p.To == "inet" && len(p.SourceNAT) == 1 && len(p.Conditions) == 1:
			viaPBR = true
		case p.PolicyRoute == "" && p.To == "outside" && len(p.SourceNAT) == 0 && len(p.Conditions) == 1:
			viaTable = true
		}
	}
	if !viaPBR || !viaTable || res.Verdict != query.VerdictAllowed {
		t.Fatalf("paths %+v verdict %s", res.Paths, res.Verdict)
	}
}
