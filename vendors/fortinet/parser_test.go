package fortinet_test

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors/fortinet"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".conf")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func parse(t *testing.T, raw string) *fm.Firewall {
	t.Helper()
	fw, err := fortinet.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic-fgt", Software: "7.4.0"})
	if err != nil {
		t.Fatal(err)
	}
	return fw
}
func traffic(t *testing.T, src, dst string, protocol, source, dest uint16) flow.Traffic {
	t.Helper()
	a, _ := flow.PrefixRange(netip.MustParsePrefix(src))
	b, _ := flow.PrefixRange(netip.MustParsePrefix(dst))
	v, err := flow.NewTraffic(8, flow.TrafficRegion{Source: a, Destination: b, Protocol: flow.Interval{Low: protocol, High: protocol}, SourcePort: flow.Interval{Low: source, High: source}, DestinationPort: flow.Interval{Low: dest, High: dest}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestScopedStagesBindRoutesAndPreserveServicePairs(t *testing.T) {
	fw := parse(t, fixture(t, "basic"))
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	if fw.Metadata().Context != "root" {
		t.Fatal(fw.Metadata())
	}
	if r := fw.Route("7"); r == nil || r.Interface() != fw.Interface("wan1") {
		t.Fatal("route before interface lost binding")
	}
	if fw.Interface("lan1").Zone() != fw.Zone("inside") {
		t.Fatal("zone identity")
	}
	for _, tt := range []struct {
		proto, src, dst uint16
		allow           bool
	}{{6, 1000, 443, true}, {6, 1001, 443, true}, {17, 2000, 53, true}, {6, 2000, 53, false}, {17, 1000, 443, false}, {6, 999, 443, false}} {
		q := policy.Request{Scope: "root", FromZone: "inside", ToZone: "wan1", Traffic: traffic(t, "192.0.2.10/32", "203.0.113.10/32", tt.proto, tt.src, tt.dst)}
		got, err := (policy.Engine{}).Query(context.Background(), fw, q)
		if err != nil || !got.Complete || got.Allowed.Empty() == tt.allow {
			t.Fatal(tt, got, err)
		}
	}
	var out bytes.Buffer
	if err := snapshot.Encode(&out, fw); err != nil {
		t.Fatal(err)
	}
	loaded, err := snapshot.Decode(&out, snapshot.DefaultMaxBytes)
	if err != nil || loaded.SemanticDigest() != fw.SemanticDigest() || loaded.Route("7").Interface() != loaded.Interface("wan1") {
		t.Fatal("snapshot identity", err)
	}
}
func TestSelectedVDOMNeverVisitsUnknownOrOtherDomainObjects(t *testing.T) {
	raw := `config global
config system interface
edit "blue-port"
set vdom "blue"
set ip 192.0.2.1 255.255.255.0
next
edit "red-port"
set vdom "red"
set ip 198.51.100.1 255.255.255.0
next
end
end
config vdom
edit "red"
config firewall unknown
edit "opaque"
set impossible yes
next
end
next
edit "blue"
config firewall address
edit "host"
set subnet 192.0.2.8 255.255.255.255
next
end
next
end
`
	fw, err := fortinet.ParseVDOM(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic"}, "blue")
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Complete() || fw.Interface("red-port") != nil || fw.Interface("blue-port") == nil || fw.Address("host") == nil || fw.Metadata().Context != "blue" {
		t.Fatal(fw.Diagnostics(), fw.Export())
	}
	raw = "config unsupported\n" + raw + "end\n"
	fw, err = fortinet.ParseVDOM(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic"}, "blue")
	if err != nil {
		t.Fatal(err)
	}
	if fw.Complete() || len(fw.Interfaces()) != 0 || fw.Address("host") != nil {
		t.Fatal("objects escaped unknown scope")
	}
}
func TestMalformedHierarchyAndUnknownConditionsCannotAuthorize(t *testing.T) {
	for _, raw := range []string{"config firewall address\nedit x\nend\n", "config firewall address\nedit x\nnext\n", "next\n"} {
		if _, err := fortinet.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{}); err == nil {
			t.Fatal("accepted malformed hierarchy", raw)
		}
	}
	raw := strings.Replace(fixture(t, "basic"), "set action accept", "set action accept\nset srcaddr-negate enable", 1)
	fw := parse(t, raw)
	q := policy.Request{Scope: "root", FromZone: "inside", ToZone: "wan1", Traffic: traffic(t, "192.0.2.10/32", "203.0.113.10/32", 6, 1000, 443)}
	got, err := (policy.Engine{}).Query(context.Background(), fw, q)
	if err != nil || got.Unknown.Empty() || !got.Allowed.Empty() {
		t.Fatal(got, err)
	}
}

func TestEditableAllAddressDoesNotNarrowImplicitDeny(t *testing.T) {
	fw := parse(t, fixture(t, "basic")+"config firewall address\nedit all\nset subnet 192.0.2.10 255.255.255.255\nnext\nend\n")
	q := policy.Request{Scope: "root", FromZone: "inside", ToZone: "wan1", Traffic: traffic(t, "192.0.2.99/32", "203.0.113.99/32", 6, 1000, 443)}
	got, err := (policy.Engine{}).Query(context.Background(), fw, q)
	if err != nil || !got.Complete || got.Denied.Empty() || !got.Unmatched.Empty() {
		t.Fatal(got, err)
	}
}
