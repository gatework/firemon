package huawei_test

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors/huawei"
)

const basic = `#
ip route-static 0.0.0.0 0 198.51.100.254 preference 70
#
firewall zone trust
 set priority 85
 add interface GigabitEthernet 1/0/1
#
firewall zone untrust
 set priority 5
 add interface GigabitEthernet1/0/2
#
interface GigabitEthernet1/0/1
 ip address 192.0.2.1 24
#
interface GigabitEthernet 1/0/2
 ip address 198.51.100.1 255.255.255.0
#
ip address-set clients type group
 address 0 address-set host
#
ip address-set host type object
 address 0 192.0.2.10 mask 32
#
ip service-set paired type object
 service 0 protocol tcp source-port 1000 to 1001 destination-port 443
 service 1 protocol udp source-port 2000 destination-port 53
#
security-policy
 rule name allow-web
  source-zone trust
  destination-zone untrust
  source-address address-set clients
  destination-address 203.0.113.10 mask 32
  service paired
  action permit
 default action deny
#
return
`

func parse(t *testing.T, raw string) *fm.Firewall {
	t.Helper()
	fw, err := huawei.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic-usg", Software: "V500R005"})
	if err != nil {
		t.Fatal(err)
	}
	return fw
}
func traffic(t *testing.T, src, dst string, proto, sport, dport uint16) flow.Traffic {
	t.Helper()
	a, _ := flow.PrefixRange(netip.MustParsePrefix(src))
	b, _ := flow.PrefixRange(netip.MustParsePrefix(dst))
	v, err := flow.NewTraffic(8, flow.Box{Source: a, Destination: b, Protocol: flow.Interval{Low: proto, High: proto}, SourcePort: flow.Interval{Low: sport, High: sport}, DestinationPort: flow.Interval{Low: dport, High: dport}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestStagesBindForwardNetworkAndObjectReferences(t *testing.T) {
	fw := parse(t, basic)
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	if fw.Interface("GigabitEthernet1/0/1").Zone() != fw.Zone("trust") {
		t.Fatal("interface zone identity")
	}
	found := false
	for _, r := range fw.Routes() {
		if !r.Record().Direct {
			found = true
			if r.Interface() != fw.Interface("GigabitEthernet1/0/2") || r.Record().Metric != 70 {
				t.Fatal(r.Record())
			}
		}
	}
	if !found {
		t.Fatal("static route missing")
	}
	for _, tt := range []struct {
		proto, src, dst uint16
		allow           bool
	}{{6, 1000, 443, true}, {6, 1001, 443, true}, {17, 2000, 53, true}, {6, 2000, 53, false}, {17, 1000, 443, false}, {6, 999, 443, false}} {
		q := policy.Request{FromZone: "trust", ToZone: "untrust", Traffic: traffic(t, "192.0.2.10/32", "203.0.113.10/32", tt.proto, tt.src, tt.dst)}
		got, err := (policy.Engine{}).Query(context.Background(), fw, q)
		if err != nil || !got.Complete || got.Allowed.Empty() == tt.allow {
			t.Fatal(tt, got, err)
		}
	}
	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, fw); err != nil {
		t.Fatal(err)
	}
	loaded, err := snapshot.Decode(&buf, snapshot.DefaultMaxBytes)
	if err != nil || loaded.SemanticDigest() != fw.SemanticDigest() || loaded.Interface("GigabitEthernet1/0/1").Zone() != loaded.Zone("trust") {
		t.Fatal("snapshot", err)
	}
}
func TestReopenedIndexedMembersReplaceWithoutReorderingRule(t *testing.T) {
	raw := strings.ReplaceAll(basic, "return\n", `ip address-set host
 address 0 192.0.2.11 mask 32
#
security-policy
 rule name allow-web
  source-address 192.0.2.12 mask 32
#
`)
	fw := parse(t, raw)
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	if got := fw.Address("host").Record().Ranges; len(got) != 1 || got[0].First.String() != "192.0.2.11" {
		t.Fatal(got)
	}
	if fw.Rule("allow-web").Record().Position != 0 {
		t.Fatal("reopen moved rule")
	}
	for _, host := range []string{"10", "11", "12"} {
		q := policy.Request{FromZone: "trust", ToZone: "untrust", Traffic: traffic(t, "192.0.2."+host+"/32", "203.0.113.10/32", 6, 1000, 443)}
		got, err := (policy.Engine{}).Query(context.Background(), fw, q)
		if err != nil || got.Allowed.Empty() != (host == "10") {
			t.Fatal(host, got, err)
		}
	}
}
func TestOpaqueBlocksAndUnsupportedMembersRemainPending(t *testing.T) {
	fw := parse(t, "unknown-feature\n interface fake0\n  ip address 10.0.0.1 24\n security-policy\n  rule name escaped\n   action permit\n#\n"+basic)
	if fw.Complete() || fw.Interface("fake0") != nil || fw.Rule("escaped") != nil {
		t.Fatal("unknown scope escaped", fw.Diagnostics())
	}
	raw := strings.Replace(basic, "  service paired", "  service paired\n  application app-unknown", 1)
	fw = parse(t, raw)
	q := policy.Request{FromZone: "trust", ToZone: "untrust", Traffic: traffic(t, "192.0.2.10/32", "203.0.113.10/32", 6, 1000, 443)}
	got, err := (policy.Engine{}).Query(context.Background(), fw, q)
	if err != nil || got.Unknown.Empty() || !got.Allowed.Empty() {
		t.Fatal(got, err)
	}
	seen := false
	for _, e := range fw.Export().Evidence {
		if strings.Contains(strings.Split(raw, "\n")[e.Span.First-1], "application app-unknown") {
			seen = true
			if e.State != fm.Pending {
				t.Fatal(e)
			}
		}
	}
	if !seen {
		t.Fatal("source evidence missing")
	}
}
