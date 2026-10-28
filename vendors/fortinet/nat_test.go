package fortinet_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors/fortinet"
)

const nativeNAT = `config firewall ippool
edit "outbound"
set type overload
set startip 198.51.100.100
set endip 198.51.100.110
next
end
config firewall vip
edit "web-public"
set extintf "wan1"
set extip 198.51.100.20
set mappedip "192.0.2.20"
next
edit "ssh-public"
set extintf "wan1"
set extip 198.51.100.21
set mappedip "192.0.2.21"
set portforward enable
set protocol tcp
set extport 2222
set mappedport 22
next
end
config firewall policy
edit 20
set srcintf "wan1"
set dstintf "inside"
set srcaddr "all"
set dstaddr "web-public" "ssh-public"
set action accept
set schedule "always"
set service "ALL"
next
edit 21
set srcintf "inside"
set dstintf "wan1"
set srcaddr "all"
set dstaddr "all"
set action accept
set schedule "always"
set service "ALL"
set nat enable
set ippool enable
set poolname "outbound"
next
end
`

func TestSeparateVIPsAndPolicyNATRetainOwnerAfterSnapshot(t *testing.T) {
	fw := parse(t, fixture(t, "basic")+nativeNAT)
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	static := fw.StaticNAT("vip:web-public")
	dynamic := fw.DynamicNAT("vip:ssh-public")
	owner := fw.DynamicNAT("policy:21")
	if static == nil || dynamic == nil || owner == nil || owner.Rule() != fw.Rule("21") || owner.SourcePool() != fw.NATPool("outbound") {
		t.Fatal("NAT catalogs or references")
	}
	if static.Record().Destination[0].Mode != fm.Offset || dynamic.Record().DestinationPorts[0].Translated.Low != 22 {
		t.Fatal("native mappings")
	}
	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, fw); err != nil {
		t.Fatal(err)
	}
	loaded, err := snapshot.Decode(&buf, snapshot.DefaultMaxBytes)
	if err != nil || loaded.DynamicNAT("policy:21").Rule() != loaded.Rule("21") {
		t.Fatal("restored owning policy", err)
	}
}
func TestDefaultServiceSourcePortAndGlobalOverride(t *testing.T) {
	raw := strings.Replace(fixture(t, "basic"), "443:1000-1001", "443", 1)
	for _, tt := range []struct {
		prefix string
		source uint16
		allow  bool
	}{{"", 0, false}, {"", 1, true}, {"config system global\nset default-service-source-port 0-65535\nend\n", 0, true}} {
		fw := parse(t, tt.prefix+raw)
		if !fw.Complete() {
			t.Fatal(fw.Diagnostics())
		}
		q := policy.Request{Scope: "root", FromZone: "inside", ToZone: "wan1", Traffic: traffic(t, "192.0.2.10/32", "203.0.113.10/32", 6, tt.source, 443)}
		got, err := (policy.Engine{}).Query(context.Background(), fw, q)
		if err != nil || !got.Complete || got.Allowed.Empty() == tt.allow {
			t.Fatal(tt, got, err)
		}
	}
}

func TestVIPPriorityAndTranslatedServiceView(t *testing.T) {
	raw := fixture(t, "basic") + strings.Replace(nativeNAT, "set service \"ALL\"", "set service \"internal-ssh\"", 1)
	raw += "config firewall service custom\nedit \"internal-ssh\"\nset tcp-portrange 22:0-65535 2222:0-65535\nnext\nend\n"
	deny := `config firewall policy
edit 19
set srcintf "wan1"
set dstintf "inside"
set srcaddr "all"
set dstaddr "all"
set action deny
set schedule "always"
set service "ALL"
set match-vip %s
next
end
`
	for _, tt := range []struct {
		mode  string
		port  uint16
		allow bool
	}{{"disable", 2222, true}, {"enable", 2222, false}, {"disable", 2223, false}} {
		configured := strings.Replace(raw, "config firewall policy\nedit 20", strings.Replace(deny, "%s", tt.mode, 1)+"config firewall policy\nedit 20", 1)
		fw := parse(t, configured)
		q := policy.Request{Scope: "root", FromZone: "wan1", ToZone: "inside", Traffic: traffic(t, "203.0.113.50/32", "198.51.100.21/32", 6, 1000, tt.port)}
		got, err := (policy.Engine{}).Query(context.Background(), fw, q)
		if err != nil || !got.Complete || got.Allowed.Empty() == tt.allow {
			t.Fatal(tt, got, err, fw.Diagnostics())
		}
	}
}

func TestFortinetNATFollowsOwningPolicyAndVIPSourcePriority(t *testing.T) {
	raw := fixture(t, "basic") + nativeNAT
	for _, tt := range []struct{ name, raw, src, want string }{
		{"pool", raw, "192.0.2.30", "198.51.100.100"},
		{"pool-before-ordinary-vip", raw, "192.0.2.20", "198.51.100.100"},
		{"forced-vip-before-pool", strings.Replace(raw, "set mappedip \"192.0.2.20\"", "set mappedip \"192.0.2.20\"\nset nat-source-vip enable", 1), "192.0.2.20", "198.51.100.20"},
		{"ordinary-vip-before-interface", strings.Replace(raw, "set ippool enable\nset poolname \"outbound\"\n", "", 1), "192.0.2.20", "198.51.100.20"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fw := parse(t, tt.raw)
			q := policy.Request{Scope: "root", FromZone: "inside", ToZone: "wan1", EgressInterface: "wan1", Traffic: traffic(t, tt.src+"/32", "203.0.113.50/32", 6, 1000, 443)}
			got, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
			if err != nil || !got.Complete || len(got.Relations) != 1 || got.Relations[0].Translated.Boxes()[0].Source.First.String() != tt.want {
				t.Fatal(got, err)
			}
			if got.Relations[0].Exact || !got.Relations[0].PossibleAllocation {
				t.Fatal("PAT presented as exact port preservation", got)
			}
		})
	}
	fw := parse(t, raw)
	// The earlier ordinary permit consumes this flow before policy 21's NAT.
	got, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{Scope: "root", FromZone: "inside", ToZone: "wan1", Traffic: traffic(t, "192.0.2.10/32", "203.0.113.10/32", 6, 1000, 443)})
	if err != nil || !got.Complete || got.Unmatched.Empty() || len(got.Relations) != 0 {
		t.Fatal(got, err)
	}
}

func TestFortinetPacketRoutesTranslatedVIPAndRetainsWireRequest(t *testing.T) {
	fw := parse(t, fixture(t, "basic")+nativeNAT)
	q := policy.PacketRequest{Request: policy.Request{Scope: "root", FromZone: "wan1", Traffic: traffic(t, "203.0.113.50/32", "198.51.100.21/32", 6, 1000, 2222)}, VRF: "root"}
	got, err := (policy.Engine{}).QueryPacket(context.Background(), fw, q)
	if err != nil || !got.Complete || len(got.Paths) != 1 {
		t.Fatal(got, err)
	}
	path := got.Paths[0]
	if path.ToZone != "inside" || path.Policy.Allowed.Empty() || path.NAT.Translated.Boxes()[0].Destination.First.String() != "192.0.2.21" || path.NAT.Translated.Boxes()[0].DestinationPort.Low != 22 || path.Original.Boxes()[0].DestinationPort.Low != 2222 {
		t.Fatal(path)
	}
}

func TestFortinetQueryUnionsVIPRegionsForSameRule(t *testing.T) {
	fw := parse(t, fixture(t, "basic")+nativeNAT)
	a := traffic(t, "203.0.113.50/32", "198.51.100.20/32", 6, 1000, 443)
	b := traffic(t, "203.0.113.50/32", "198.51.100.21/32", 6, 1000, 2222)
	input, err := a.Union(b, 8)
	if err != nil {
		t.Fatal(err)
	}
	got, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Scope: "root", FromZone: "wan1", ToZone: "inside", Traffic: input})
	if err != nil || !got.Complete || len(got.Trace) != 1 {
		t.Fatal("one rule must retain all its effective regions", got, err)
	}
	if contains, err := got.Trace[0].Traffic.Contains(input, 8); err != nil || !contains {
		t.Fatal(err, got)
	}
}

func TestFortinetPoolLocalAddressDoesNotBecomeOrdinaryRoutedPacket(t *testing.T) {
	fw := parse(t, fixture(t, "basic")+nativeNAT)
	q := policy.PacketRequest{Request: policy.Request{Scope: "root", FromZone: "inside", Traffic: traffic(t, "192.0.2.30/32", "198.51.100.100/32", 6, 1000, 443)}}
	got, err := (policy.Engine{}).QueryPacket(context.Background(), fw, q)
	if err != nil || got.Unknown.Empty() || got.Complete || len(got.Paths) != 0 {
		t.Fatal("IP pool local-address behavior was ignored", got, err)
	}
}

func TestFortinetUnknownMatchVIPDefaultAndServiceViewStayUnknown(t *testing.T) {
	raw := fixture(t, "basic") + nativeNAT
	raw = strings.Replace(raw, "config firewall policy\nedit 20", `config firewall policy
edit 19
set srcintf "wan1"
set dstintf "inside"
set srcaddr "all"
set dstaddr "all"
set action deny
set schedule "always"
set service "ALL"
next
end
config firewall policy
edit 20`, 1)
	fw, err := fortinet.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	q := policy.Request{Scope: "root", FromZone: "wan1", ToZone: "inside", Traffic: traffic(t, "203.0.113.50/32", "198.51.100.20/32", 6, 1000, 443)}
	got, err := (policy.Engine{}).Query(context.Background(), fw, q)
	if err != nil || got.Unknown.Empty() || !got.Allowed.Empty() {
		t.Fatal(got, err)
	}
	raw = strings.Replace(fixture(t, "basic")+nativeNAT, "set service \"ALL\"", "set service \"external-only\"", 1) + "config firewall service custom\nedit external-only\nset tcp-portrange 2222:0-65535\nnext\nend\n"
	fw = parse(t, raw)
	q.Traffic = traffic(t, "203.0.113.50/32", "198.51.100.21/32", 6, 1000, 2222)
	got, err = (policy.Engine{}).Query(context.Background(), fw, q)
	if err != nil || got.Unknown.Empty() || !got.Allowed.Empty() {
		t.Fatal(got, err)
	}
}

func TestFortinetMissingIngressCannotEstablishVIPDenial(t *testing.T) {
	fw := parse(t, fixture(t, "basic")+nativeNAT)
	got, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Scope: "root", ToZone: "inside", Traffic: traffic(t, "203.0.113.50/32", "198.51.100.20/32", 6, 1000, 443)})
	if err != nil || got.Unknown.Empty() || !got.Denied.Empty() {
		t.Fatal(got, err)
	}
}

func TestFortinetDeclaredRiskCannotFlattenVIPToUnrestrictedAddress(t *testing.T) {
	fw := parse(t, fixture(t, "basic")+nativeNAT)
	q := policy.Request{Scope: "root", FromZone: "wan1", ToZone: "inside", Traffic: traffic(t, "203.0.113.50/32", "198.51.100.21/32", 6, 1000, 5555)}
	rows, err := (analysis.RiskAnalyzer{}).Assess(context.Background(), fw, q, analysis.RiskDefinition{ID: "test", Version: "1", Mode: analysis.Declared, Relation: analysis.Intersects, Traffic: q.Traffic})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Rule == "20" && row.Value != analysis.Unknown {
			t.Fatal("generic declared match ignored VIP port selection", row)
		}
	}
}

func TestFortinetPoolInterfaceCannotBeIgnoredByNATQuery(t *testing.T) {
	raw := strings.Replace(fixture(t, "basic")+nativeNAT, "set type overload", "set type overload\nset associated-interface lan1", 1)
	fw := parse(t, raw)
	q := policy.Request{Scope: "root", FromZone: "inside", ToZone: "wan1", Traffic: traffic(t, "192.0.2.30/32", "203.0.113.50/32", 6, 1000, 443)}
	got, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
	if err != nil || got.Unknown.Empty() || len(got.Relations) != 0 {
		t.Fatal(got, err)
	}
}
