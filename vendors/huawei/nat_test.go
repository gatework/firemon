package huawei_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
)

const nativeNAT = `nat address-group outbound 1
 section 0 198.51.100.100 198.51.100.110
 mode pat
#
nat address-group preserved 2
 section 0 198.51.100.120
 mode no-pat global
#
destination-nat address-group backend 1
 section 0 192.0.2.20
#
nat server fixed zone untrust global 198.51.100.50 inside 192.0.2.50
nat server https zone untrust protocol tcp global 198.51.100.60 8443 inside 192.0.2.60 443 no-reverse
nat-policy
 rule name bypass
  source-zone trust
  destination-zone untrust
  destination-address 203.0.113.254 mask 32
  action no-nat
 rule name pooled
  source-zone trust
  destination-zone untrust
  source-address address-set clients
  action source-nat address-group outbound
 rule name inbound
  source-zone untrust
  destination-address 198.51.100.70 mask 32
  service protocol tcp destination-port 8080
  action destination-nat address-group backend 80
#
`

func TestNATRetainsSeparateServerPoolAndPolicyObjects(t *testing.T) {
	fw := parse(t, strings.Replace(basic, "return\n", nativeNAT, 1))
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	static := fw.StaticNAT("server:fixed")
	if static == nil || !static.Record().Bidirectional || static.Record().Destination[0].Translated.First.String() != "192.0.2.50" {
		t.Fatal("static server missing")
	}
	port := fw.DynamicNAT("server:https")
	if port == nil || port.Record().DestinationPorts[0].Original.Low != 8443 || port.Record().DestinationPorts[0].Translated.Low != 443 {
		t.Fatal("port server missing")
	}
	source := fw.DynamicNAT("policy:pooled")
	if source == nil || source.Record().SourceMode != fm.DynamicIPPort || source.SourcePool() != fw.NATPool("source:outbound") {
		t.Fatal("source allocation identity")
	}
	if fw.NATPool("destination:backend") == nil {
		t.Fatal("destination pool missing")
	}
	if !fw.DynamicNAT("policy:bypass").Record().Match.AnyService {
		t.Fatal("exemption conditions")
	}
	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, fw); err != nil {
		t.Fatal(err)
	}
	loaded, err := snapshot.Decode(&buf, snapshot.DefaultMaxBytes)
	if err != nil || loaded.DynamicNAT("policy:pooled").SourcePool() != loaded.NATPool("source:outbound") || loaded.SemanticDigest() != fw.SemanticDigest() {
		t.Fatal(err)
	}
}

func TestNativeNATPriorityAndOriginalPortSelection(t *testing.T) {
	fw := parse(t, strings.Replace(basic, "return\n", nativeNAT, 1))
	for _, tt := range []struct {
		source, dest, from, to string
		port                   uint16
		id                     fm.ID
		src, dst               string
		translatedPort         uint16
		possible               bool
	}{
		{"203.0.113.1", "198.51.100.50", "untrust", "trust", 443, "server:fixed", "203.0.113.1", "192.0.2.50", 443, false},
		{"192.0.2.50", "203.0.113.1", "trust", "untrust", 443, "server:fixed", "198.51.100.50", "203.0.113.1", 443, false},
		{"203.0.113.1", "198.51.100.60", "untrust", "trust", 8443, "server:https", "203.0.113.1", "192.0.2.60", 443, false},
		{"192.0.2.10", "203.0.113.1", "trust", "untrust", 443, "policy:pooled", "198.51.100.100", "203.0.113.1", 443, true},
		{"192.0.2.10", "203.0.113.254", "trust", "untrust", 443, "policy:bypass", "192.0.2.10", "203.0.113.254", 443, false},
		{"203.0.113.1", "198.51.100.70", "untrust", "trust", 8080, "policy:inbound", "203.0.113.1", "192.0.2.20", 80, false},
	} {
		t.Run(string(tt.id)+tt.source, func(t *testing.T) {
			q := policy.Request{FromZone: fm.ID(tt.from), ToZone: fm.ID(tt.to), Traffic: traffic(t, tt.source+"/32", tt.dest+"/32", 6, 1000, tt.port)}
			got, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
			if err != nil || !got.Complete || len(got.Relations) != 1 {
				t.Fatal(got, err)
			}
			r := got.Relations[0]
			b := r.Translated.Boxes()[0]
			if r.ID != tt.id || b.Source.First.String() != tt.src || b.Destination.First.String() != tt.dst || b.DestinationPort.Low != tt.translatedPort || r.PossibleAllocation != tt.possible {
				t.Fatal(r)
			}
		})
	}
	q := policy.Request{FromZone: "untrust", ToZone: "trust", Traffic: traffic(t, "203.0.113.1/32", "198.51.100.60/32", 6, 1000, 443)}
	got, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
	if err != nil || !got.Complete || len(got.Relations) != 0 || got.Unmatched.Empty() {
		t.Fatal("inside port incorrectly selected public mapping", got, err)
	}
}

func TestOverlappingServerMappingsHaveNoInventedNamePriority(t *testing.T) {
	raw := strings.Replace(basic, "return\n", nativeNAT+"nat server conflict global 198.51.100.50 inside 192.0.2.99\n", 1)
	fw := parse(t, raw)
	got, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{FromZone: "untrust", ToZone: "trust", Traffic: traffic(t, "203.0.113.1/32", "198.51.100.50/32", 6, 1000, 443)})
	if err != nil || got.Complete || got.Unknown.Empty() || len(got.Relations) > 0 {
		t.Fatal(got, err)
	}
}

func TestMixedServerAndOppositePolicyTranslationNeedsNativeEvidence(t *testing.T) {
	raw := strings.Replace(basic, "return\n", nativeNAT+`nat-policy
 rule name hairpin-source
  source-zone untrust
  destination-zone trust
  action source-nat address-group outbound
#
`, 1)
	fw := parse(t, raw)
	q := policy.Request{FromZone: "untrust", ToZone: "trust", Traffic: traffic(t, "203.0.113.10/32", "198.51.100.50/32", 6, 1000, 443)}
	got, err := (policy.Engine{}).QueryNAT(context.Background(), fw, q)
	if err != nil || got.Unknown.Empty() || len(got.Relations) != 0 {
		t.Fatal("mixed chain inferred from server precedence", got, err)
	}
}
func TestUnsupportedNATOptionsNeverBecomeBroadMappings(t *testing.T) {
	for _, text := range []string{
		"nat server x protocol tcp global 198.51.100.2 443 inside 192.0.2.2 443\n",
		"nat server x global 198.51.100.2 198.51.100.3 inside 192.0.2.2\n",
		"nat server x global 198.51.100.2 inside 192.0.2.2 unr-route\n",
		"nat address-group x\n section 0 198.51.100.2\n smart-nopat\n#\n",
		"nat-policy\n rule name invalid\n  action destination-nat static port-to-port address 192.0.2.2 80\n#\n",
		"nat-policy\n rule name invalid\n  action destination-nat address 192.0.2.2 80\n#\n",
	} {
		t.Run(text, func(t *testing.T) {
			fw := parse(t, strings.Replace(basic, "return\n", text, 1))
			if fw.Complete() {
				t.Fatal("unsupported NAT marked complete")
			}
		})
	}
}
