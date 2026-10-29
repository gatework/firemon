package hillstone_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/hillstone"
)

func parse(t *testing.T, text string) *fm.Firewall {
	t.Helper()
	f, err := hillstone.Parse(context.Background(), config.Source{Text: text, Complete: true}, fm.Metadata{Device: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestHillstoneLogEventsAndUnspecifiedLogRemainDistinct(t *testing.T) {
	for _, tc := range []struct {
		value      string
		start, end fm.Status
	}{{"log session-start", fm.Known, fm.Irrelevant}, {"log session-end", fm.Irrelevant, fm.Known}, {"log", fm.Unknown, fm.Unknown}} {
		t.Run(tc.value, func(t *testing.T) {
			fw := parse(t, "policy-global\nrule id 1\nsrc-addr any\ndst-addr any\nservice any\naction permit\n"+tc.value+"\nexit\nexit\n")
			if !fw.Complete() {
				t.Fatal(fw.Diagnostics())
			}
			r := fw.Rule("1").Record()
			if r.Log != fm.Known || r.LogStart != tc.start || r.LogEnd != tc.end {
				t.Fatal("log events lost", r)
			}
		})
	}
}
func TestNativeStagesBindReferencesAndKeepDistinctNATObjects(t *testing.T) {
	raw, err := os.ReadFile("testdata/basic.cfg")
	if err != nil {
		t.Fatal(err)
	}
	explicit := strings.Replace(string(raw), "trans-to 198.51.100.100\n", "trans-to 198.51.100.100 mode dynamicport\n", 1)
	fw := parse(t, explicit+"bnatrule id 3 virtual ip 203.0.113.0/24 real ip 192.0.2.0/24\n")
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	if fw.Interface("eth0").Zone() != fw.Zone("inside") || fw.Interface("eth0").Scope() != "trust-vr" {
		t.Fatal("zone context not bound")
	}
	if len(fw.Routes()) != 2 || len(fw.Rules()) != 1 {
		t.Fatal("objects missing")
	}
	if len(fw.DynamicNATs()) != 2 || len(fw.StaticNATs()) != 1 {
		t.Fatal("native NAT types lost")
	}
	if fw.StaticNAT("bnat:3").Record().Source[0].Mode != fm.Offset {
		t.Fatal("explicit static mapping missing")
	}
	if fw.DynamicNAT("trust-vr/snat:1").SourcePool() == nil {
		t.Fatal("SNAT pool not referenced")
	}
}
func TestUnknownNativeBlockAndQuotedTextCannotCreateFirewallObjects(t *testing.T) {
	fw := parse(t, "admin user operator\nrule id 99\ninterface bad\nexit\nhostname \"text\ninterface fake\n\"\ninterface real\n ip address 192.0.2.1/24\nexit\n")
	if len(fw.Rules()) != 0 || len(fw.Interfaces()) != 1 || fw.Interface("real") == nil {
		t.Fatal("scope escaped")
	}
}
func TestUnknownRuleMemberCannotBecomeUnrestrictedPermit(t *testing.T) {
	fw := parse(t, "policy-global\nrule id 1\nsrc-addr any\ndst-addr any\nservice any\napplication custom\naction permit\nexit\nexit\n")
	if fw.Complete() || len(fw.Rule("1").Record().Match.Unsupported) == 0 {
		t.Fatal("unsupported selector lost")
	}
}
func TestOutOfOrderInterfaceAndRouteUseLaterZoneAndLongestPrefix(t *testing.T) {
	fw := parse(t, "ip vrouter blue\nip route 0.0.0.0/0 192.0.2.200\nexit\ninterface eth1\nzone inside\nip address 192.0.2.129/25\nexit\nzone inside\nvrouter blue\nexit\n")
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	found := false
	for _, r := range fw.Routes() {
		if !r.Record().Direct {
			found = true
			if r.Interface() != fw.Interface("eth1") {
				t.Fatal("route bound before interface existed")
			}
		}
	}
	if !found {
		t.Fatal("static route missing")
	}
}
func TestTruncatedBlockAndUnknownNATRemainIncomplete(t *testing.T) {
	for _, text := range []string{"interface eth0\nip address 192.0.2.1/24\n", "snatrule id 1 from any to any service any trans-to 203.0.113.1 made-up yes\n"} {
		t.Run(strings.Fields(text)[0], func(t *testing.T) {
			fw := parse(t, text)
			if fw.Complete() {
				t.Fatal("incomplete source accepted")
			}
		})
	}
}

func TestUnspecifiedSNATModePreservesUnknownAllocation(t *testing.T) {
	raw, err := os.ReadFile("testdata/basic.cfg")
	if err != nil {
		t.Fatal(err)
	}
	fw := parse(t, string(raw))
	if fw.Complete() || fw.DynamicNAT("trust-vr/snat:1").Record().SourceMode != fm.UnknownTranslation {
		t.Fatal("undeclared allocation guessed")
	}
}

func TestRepeatedRuleBlocksAppendMembersWithoutDuplicateIdentity(t *testing.T) {
	fw := parse(t, "address a\nip 192.0.2.1/32\nexit\naddress b\nip 192.0.2.2/32\nexit\npolicy-global\nrule id 10\nsrc-addr a\ndst-addr any\nservice any\naction permit\nexit\nrule id 10\nsrc-addr b\nexit\nexit\n")
	if !fw.Complete() || len(fw.Rules()) != 1 || len(fw.Rule("10").Sources()) != 2 {
		t.Fatal("repeated rule lost identity or members", fw.Diagnostics())
	}
}
func TestEmptyAddressPredeclarationDoesNotShadowActualDefinition(t *testing.T) {
	fw := parse(t, "address a\nexit\naddress a\nip 192.0.2.1/32\nexit\n")
	if !fw.Complete() || len(fw.Addresses()) != 1 || fw.Address("a").Set().Empty() {
		t.Fatal("predeclaration shadowed definition", fw.Diagnostics())
	}
}

func TestNATServiceGroupDAGDoesNotDuplicatePortMappings(t *testing.T) {
	text := "address public\nip 203.0.113.10/32\nexit\naddress private\nip 192.0.2.10/32\nexit\nservice web\ntcp dst-port 443 443\nexit\n"
	previous := "web"
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("g%d", i)
		text += fmt.Sprintf("servgroup %s\nservice %s\nservice %s\nexit\n", name, previous, previous)
		previous = name
	}
	text += fmt.Sprintf("dnatrule id 1 from any to public service %s trans-to private port 8443\n", previous)
	fw := parse(t, text)
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	if got := len(fw.DynamicNAT("dnat:1").Record().DestinationPorts); got != 1 {
		t.Fatalf("expanded DAG into %d duplicate mappings", got)
	}
}

func TestNATNativeIDsAreScopedByChainAndVRF(t *testing.T) {
	raw := "ip vrouter blue\nsnatrule id 1 from any to any service any trans-to 203.0.113.1 mode dynamicport\ndnatrule id 1 from any to ip 198.51.100.1 service any trans-to 192.0.2.1\nexit\nip vrouter red\nsnatrule id 1 from any to any service any trans-to 203.0.113.2 mode dynamicport\nexit\n"
	fw := parse(t, raw)
	if !fw.Complete() || len(fw.DynamicNATs()) != 3 {
		t.Fatal("native namespaces collapsed", fw.Diagnostics())
	}
	for _, id := range []fm.ID{"blue/snat:1", "blue/dnat:1", "red/snat:1"} {
		n := fw.DynamicNAT(id)
		if n == nil || n.Name() != "1" {
			t.Fatalf("missing native identity %s", id)
		}
	}
	if fw.DynamicNAT("blue/dnat:1").Record().Order.Stage >= fw.DynamicNAT("blue/snat:1").Record().Order.Stage {
		t.Fatal("source/destination stages lost")
	}
}

func TestExplicitStaticSNATUsesStaticCatalogAndDynamicIPUsesPool(t *testing.T) {
	fw := parse(t, "snatrule id 1 from ip 192.0.2.0/24 to any service any trans-to 203.0.113.0/24 mode static\nsnatrule id 2 from ip 198.51.100.0/24 to any service any trans-to 203.0.113.128/25 mode dynamicip\n")
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	s, d := fw.StaticNAT("snat:1"), fw.DynamicNAT("snat:2")
	if s == nil || d == nil || s.Record().Bidirectional || len(s.Record().Source) != 1 || s.Record().Source[0].Mode != fm.Offset || d.Record().SourceMode != fm.DynamicIP {
		t.Fatal("explicit modes lost native meanings")
	}
}
