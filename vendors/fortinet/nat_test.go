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
	if fw.Address("vip:web-public").VIPStaticNAT() != static || fw.Address("vip:ssh-public").VIPDynamicNAT() != dynamic || fw.StaticNAT("vip-source:web-public").SourceVIP() != fw.Address("vip:web-public") {
		t.Fatal("VIP graph associations were not explicit shared references")
	}
	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, fw); err != nil {
		t.Fatal(err)
	}
	loaded, err := snapshot.Decode(&buf, snapshot.DefaultMaxBytes)
	if err != nil || loaded.DynamicNAT("policy:21").Rule() != loaded.Rule("21") {
		t.Fatal("restored owning policy", err)
	}
	if loaded.Address("vip:web-public").VIPStaticNAT() != loaded.StaticNAT("vip:web-public") || loaded.Address("vip:ssh-public").VIPDynamicNAT() != loaded.DynamicNAT("vip:ssh-public") || loaded.StaticNAT("vip-source:web-public").SourceVIP() != loaded.Address("vip:web-public") {
		t.Fatal("VIP graph associations lost shared identity after snapshot")
	}
}

func TestVIPAddressesAndGroupsRetainSelectedVDOMScope(t *testing.T) {
	raw := fixture(t, "basic") + nativeNAT + "config firewall vipgrp\nedit public-services\nset member web-public ssh-public\nnext\nend\n"
	fw := parse(t, raw)
	for _, id := range []fm.ID{"vip:web-public", "vip:ssh-public"} {
		if got := fw.Address(id).Scope(); got != "root" {
			t.Errorf("address %s scope = %q, want selected VDOM root", id, got)
		}
	}
	if got := fw.AddressGroup("vip-group:public-services").Scope(); got != "root" {
		t.Errorf("VIP group scope = %q, want selected VDOM root", got)
	}
}

func TestVIPGroupRejectsOrdinaryAddressWithVIPPrefixedNativeName(t *testing.T) {
	raw := fixture(t, "basic") + `config firewall address
edit "vip:ordinary"
set subnet 198.51.100.42 255.255.255.255
next
end
config firewall vipgrp
edit "public-services"
set member "vip:ordinary"
next
end
`
	fw := parse(t, raw)
	if fw.Complete() || !fw.AddressGroup("vip-group:public-services").HasUnsupported() {
		t.Fatal("VIP group inferred membership from the native address ID", fw.Diagnostics())
	}
	if a := fw.Address("vip:ordinary"); a.Record().VIP != (fm.NATRef{}) || a.VIPStaticNAT() != nil || a.VIPDynamicNAT() != nil {
		t.Fatal("ordinary address acquired a VIP association")
	}
}

func TestVIPQueriesFollowExplicitReferencesAcrossIndependentNativeIdentities(t *testing.T) {
	raw := strings.Replace(fixture(t, "basic")+nativeNAT, "set mappedip \"192.0.2.20\"", "set mappedip \"192.0.2.20\"\nset nat-source-vip enable", 1)
	raw = strings.Replace(raw, "set dstaddr \"web-public\" \"ssh-public\"", "set dstaddr \"public-services\"", 1)
	raw += "config firewall addrgrp\nedit public-services\nset member web-public ssh-public\nnext\nend\n"
	d := parse(t, raw).Export()
	addressIDs := map[fm.ID]fm.ID{"vip:web-public": "public-static-address", "vip:ssh-public": "public-port-address"}
	for i := range d.Addresses {
		r := &d.Addresses[i]
		if id, ok := addressIDs[r.ID]; ok {
			r.ID, r.Name, r.VIP.ID = id, "independent-address-name", "same-native-map-id"
		}
	}
	for i := range d.AddressGroups {
		for j := range d.AddressGroups[i].Members {
			ref := &d.AddressGroups[i].Members[j]
			if id, ok := addressIDs[ref.ID]; ok {
				ref.ID = id
			}
		}
	}
	for i := range d.StaticNATs {
		r := &d.StaticNATs[i]
		if r.ID == "vip:web-public" {
			r.ID, r.Name = "same-native-map-id", "independent-destination-map-name"
		}
		if r.ID == "vip-source:web-public" {
			r.ID, r.Name, r.SourceVIP.ID = "native-source-map-id", "independent-source-map-name", "public-static-address"
		}
	}
	for i := range d.DynamicNATs {
		if r := &d.DynamicNATs[i]; r.ID == "vip:ssh-public" {
			r.ID, r.Name = "same-native-map-id", "independent-port-map-name"
		}
	}
	fw, err := fm.Seal(d)
	if err != nil || !fw.Complete() {
		t.Fatal(fw, err)
	}
	for _, tc := range []struct {
		name string
		dst  string
		port uint16
	}{
		{"static-vip", "198.51.100.20/32", 443},
		{"port-vip", "198.51.100.21/32", 2222},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := policy.Request{Scope: "root", FromZone: "wan1", ToZone: "inside", Traffic: traffic(t, "203.0.113.50/32", tc.dst, 6, 1000, tc.port)}
			got, err := (policy.Engine{}).Query(context.Background(), fw, q)
			if err != nil || !got.Complete || got.Allowed.Empty() {
				t.Fatal("VIP policy followed matching names or untyped IDs", got, err)
			}
		})
	}
	outbound := policy.Request{Scope: "root", FromZone: "inside", ToZone: "wan1", EgressInterface: "wan1", Traffic: traffic(t, "192.0.2.20/32", "203.0.113.50/32", 6, 1000, 443)}
	nat, err := (policy.Engine{}).QueryNAT(context.Background(), fw, outbound)
	if err != nil || !nat.Complete || len(nat.Relations) != 1 || nat.Relations[0].ID != "native-source-map-id" || nat.Relations[0].Translated.Regions()[0].Source.First.String() != "198.51.100.20" {
		t.Fatal("source VIP mapping followed reconstructed name or ID", nat, err)
	}
	packet := policy.PacketRequest{Request: policy.Request{Scope: "root", FromZone: "wan1", Traffic: traffic(t, "203.0.113.50/32", "198.51.100.21/32", 6, 1000, 2222)}, VRF: "root"}
	got, err := (policy.Engine{}).QueryPacket(context.Background(), fw, packet)
	if err != nil || !got.Complete || len(got.Paths) != 1 || got.Paths[0].Policy.Allowed.Empty() || got.Paths[0].NAT.Translated.Regions()[0].Destination.First.String() != "192.0.2.21" {
		t.Fatal("packet lookup lost explicit port VIP identity", got, err)
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
			if err != nil || !got.Complete || len(got.Relations) != 1 || got.Relations[0].Translated.Regions()[0].Source.First.String() != tt.want {
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
	if path.ToZone != "inside" || path.Policy.Allowed.Empty() || path.NAT.Translated.Regions()[0].Destination.First.String() != "192.0.2.21" || path.NAT.Translated.Regions()[0].DestinationPort.Low != 22 || path.Original.Regions()[0].DestinationPort.Low != 2222 {
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
	if err != nil || !got.Complete || len(got.Decisions) != 1 {
		t.Fatal("one rule must retain all its effective regions", got, err)
	}
	if contains, err := got.Decisions[0].Traffic.Contains(input, 8); err != nil || !contains {
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
	rows, err := (analysis.RiskAnalyzer{}).Analyze(context.Background(), fw, q, analysis.RiskDefinition{ID: "test", Version: "1", Mode: analysis.Declared, Relation: analysis.Intersects, Traffic: q.Traffic})
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
