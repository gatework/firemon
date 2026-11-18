package hillstone_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
	"github.com/gatework/firemon/vendors/hillstone"
)

// accuracyConf is a site edge with the rule shapes found in production
// configurations: a rule left with only an action, an action-less rule, a
// service list with a name the book lacks, and an exclusion-only object.
const accuracyConf = `zone "inside"
exit
zone "outside"
exit
zone "l2-a" l2
exit
interface ethernet0/1
  zone  "inside"
  ip address 10.0.0.1 255.255.0.0
exit
interface ethernet0/2
  zone  "outside"
  ip address 203.0.113.2 255.255.255.252
exit
interface ethernet0/3
  zone  "l2-a"
exit
address "blocked-hosts"
  ip 10.0.3.0/24
exit
address "public"
  exclude ip 10.0.0.0/8
  exclude ip 192.168.0.0/16
exit
ip vrouter "trust-vr"
  ip route 0.0.0.0/0 203.0.113.1
exit
rule id 6
  action permit
exit
rule id 50
exit
rule id 3
  action deny
  src-addr "blocked-hosts"
  dst-addr "Any"
  service "Any"
exit
rule id 7
  action deny
  src-addr "Any"
  dst-addr "public"
  service "HTTP-EXT"
  service "HTTPS"
exit
rule id 1
  action permit
  src-addr "Any"
  dst-addr "Any"
  service "Any"
exit
`

func accuracyEngine(t *testing.T) (*firemon.Firewall, *query.Engine) {
	t.Helper()
	fw := compileText(t, accuracyConf)
	return fw, query.New(fw, query.Options{Now: func() time.Time { return time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC) }})
}

func decidingRule(t *testing.T, e *query.Engine, src, dst string, port uint16) (string, query.Outcome, int) {
	t.Helper()
	s, _ := traffic.ParseAddressSet(src)
	d, _ := traffic.ParseAddressSet(dst)
	res, err := e.Query(query.Request{Src: s, Dst: d, Service: traffic.PortService(traffic.ProtocolTCP, traffic.Port(port))})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Paths) != 1 || len(res.Paths[0].Decisions) != 1 {
		t.Fatalf("want one decision: %+v", res.Paths)
	}
	d0 := res.Paths[0].Decisions[0]
	id := "(default)"
	if d0.Rule != nil {
		id = d0.Rule.ID()
	}
	return id, d0.Outcome, len(d0.Possible)
}

func TestV1_IncompleteRulesNeverMatch(t *testing.T) {
	t.Parallel()
	fw, e := accuracyEngine(t)
	for _, id := range []string{"6", "50"} {
		r, _ := fw.Rule(id)
		if r.Spec().Incomplete == "" || !r.Ignored() {
			t.Errorf("rule %s must be incomplete and ignored: %+v", id, r.Spec())
		}
	}
	if id, o, _ := decidingRule(t, e, "10.0.3.5", "8.8.8.8", 80); id != "3" || o != query.OutcomeDeny {
		t.Fatalf("an action-only rule above must not permit: decided by %s %s", id, o)
	}
}

func TestV3_CertainPartOfUndecidableRuleDecides(t *testing.T) {
	t.Parallel()
	fw, e := accuracyEngine(t)
	r, _ := fw.Rule("7")
	if r.Decidable() {
		t.Fatal("rule 7 names an unknown service")
	}
	if _, ok := r.Certain(); !ok {
		t.Fatal("an unknown service in a list can only add to the match")
	}
	if id, o, possible := decidingRule(t, e, "10.0.9.9", "8.8.8.8", 443); id != "7" || o != query.OutcomeDeny || possible != 0 {
		t.Fatalf("HTTPS certainly matches rule 7: got %s %s (%d possible)", id, o, possible)
	}
	// Other ports may be HTTP-EXT: rule 7 may deny them first.
	if id, o, possible := decidingRule(t, e, "10.0.9.9", "8.8.8.8", 8080); id != "1" || o != query.OutcomeUnknown || possible != 1 {
		t.Fatalf("tcp/8080 may be HTTP-EXT: got %s %s (%d possible)", id, o, possible)
	}
}

func TestV5_ExclusionOnlyObjectIsEverythingElse(t *testing.T) {
	t.Parallel()
	fw, _ := accuracyEngine(t)
	set, ok := fw.Address("public")
	if !ok || !set.Contains(netip.MustParseAddr("8.8.8.8")) || set.Contains(netip.MustParseAddr("10.1.1.1")) {
		t.Fatalf("public = %s", set)
	}
}

func TestV7_TransparentInterfacesNeedZones(t *testing.T) {
	t.Parallel()
	fw, e := accuracyEngine(t)
	if !fw.Bridges() {
		t.Fatal("ethernet0/3 is bound to a layer-2 zone")
	}
	s, _ := traffic.ParseAddressSet("10.0.9.9")
	res, err := e.Query(query.Request{Src: s, Dst: s, Service: traffic.AnyService()})
	if err != nil || !res.ZonesNeeded {
		t.Fatalf("zones needed: %v %v", res, err)
	}
}

func TestV6_ComplementaryPolicyRouteBranchesFold(t *testing.T) {
	t.Parallel()
	conf := natOrderConf + `pbr-policy "inside-pbr" vrouter "trust-vr"
  match id 9
    src-addr "vip-users"
    dst-addr "Any"
    service "Any"
    nexthop 198.51.100.254
  exit
exit
`
	cfg := mustParse(t, hillstone.Options{}, conf)
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e := query.New(fw, query.Options{})
	res := ask(t, e, "10.0.5.7", "8.8.8.8")
	if len(res.Paths) != 1 || len(res.Paths[0].Conditions) != 0 || res.Paths[0].To != "inet" {
		t.Fatalf("both branches of entry 8 reach inet for vip-users: %+v", res.Paths)
	}
}
