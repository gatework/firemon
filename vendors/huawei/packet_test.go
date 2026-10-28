package huawei_test

import (
	"context"
	"strings"
	"testing"

	"github.com/gatework/firemon/policy"
)

func TestPacketRoutesAfterDNATAndUsesTranslatedDestinationService(t *testing.T) {
	raw := strings.Replace(basic, "return\n", nativeNAT+`security-policy
 rule name published
  source-zone untrust
  destination-zone trust
  destination-address 192.0.2.60 mask 32
  service protocol tcp destination-port 443
  action permit
#
`, 1)
	fw := parse(t, raw)
	q := policy.PacketRequest{Request: policy.Request{FromZone: "untrust", Traffic: traffic(t, "203.0.113.10/32", "198.51.100.60/32", 6, 1000, 8443)}}
	got, err := (policy.Engine{}).QueryPacket(context.Background(), fw, q)
	if err != nil || !got.Complete || len(got.Paths) != 1 {
		t.Fatal(got, err)
	}
	path := got.Paths[0]
	if path.ToZone != "trust" || path.Policy.Allowed.Empty() || path.Original.Boxes()[0].DestinationPort.Low != 8443 || path.Policy.Allowed.Boxes()[0].DestinationPort.Low != 443 || path.NAT.Translated.Boxes()[0].Destination.First.String() != "192.0.2.60" {
		t.Fatal(path)
	}
	wrong := parse(t, strings.Replace(raw, "service protocol tcp destination-port 443", "service protocol tcp destination-port 8443", 1))
	got, err = (policy.Engine{}).QueryPacket(context.Background(), wrong, q)
	if err != nil || !got.Complete || len(got.Paths) != 1 || got.Paths[0].Policy.Denied.Empty() {
		t.Fatal(got, err)
	}
}
func TestPacketEvaluatesPolicyBeforeSourceAllocation(t *testing.T) {
	fw := parse(t, strings.Replace(basic, "return\n", nativeNAT, 1))
	for _, dest := range []string{"203.0.113.10", "203.0.113.11"} {
		q := policy.PacketRequest{Request: policy.Request{FromZone: "trust", Traffic: traffic(t, "192.0.2.10/32", dest+"/32", 6, 1000, 443)}}
		got, err := (policy.Engine{}).QueryPacket(context.Background(), fw, q)
		if err != nil || !got.Complete || len(got.Paths) != 1 {
			t.Fatal(got, err)
		}
		path := got.Paths[0]
		allow := dest == "203.0.113.10"
		if path.Policy.Allowed.Empty() == allow {
			t.Fatal(path)
		}
		want := "192.0.2.10"
		if allow {
			want = "198.51.100.100"
		}
		if path.NAT.Translated.Boxes()[0].Source.First.String() != want {
			t.Fatal("source allocation before policy", path)
		}
	}
}

func TestPacketSelectsWholeBidirectionalPolicyUsingPostDNATRoute(t *testing.T) {
	raw := strings.Replace(basic, "return\n", `nat address-group outbound
 section 0 192.0.2.200
#
nat-policy
 rule name pair
  source-zone untrust
  destination-zone trust
  destination-address 198.51.100.80 mask 32
  service protocol tcp destination-port 8443
  action source-nat address-group outbound
  action destination-nat address 192.0.2.80 443
 rule name later-source
  source-zone untrust
  action source-nat easy-ip
#
security-policy
 rule name published
  source-zone untrust
  destination-zone trust
  source-address 203.0.113.10 mask 32
  destination-address 192.0.2.80 mask 32
  service protocol tcp destination-port 443
  action permit
#
`, 1)
	fw := parse(t, raw)
	q := policy.PacketRequest{Request: policy.Request{FromZone: "untrust", Traffic: traffic(t, "203.0.113.10/32", "198.51.100.80/32", 6, 1000, 8443)}}
	// The later ambiguous Easy-IP record is deliberately incomplete. Remove it
	// for this positive case; a separate check retains it and requires unknown.
	good := strings.Replace(raw, " rule name later-source\n  source-zone untrust\n  action source-nat easy-ip\n", "", 1)
	got, err := (policy.Engine{}).QueryPacket(context.Background(), parse(t, good), q)
	if err != nil || !got.Complete || len(got.Paths) != 1 {
		t.Fatal(got, err)
	}
	p := got.Paths[0]
	b := p.NAT.Translated.Boxes()[0]
	if p.Policy.Allowed.Empty() || p.ToZone != "trust" || p.NAT.ID != "policy:pair" || len(p.NAT.Steps) != 1 || b.Source.First.String() != "192.0.2.200" || b.Destination.First.String() != "192.0.2.80" || b.DestinationPort.Low != 443 {
		t.Fatal(p)
	}
	got, err = (policy.Engine{}).QueryPacket(context.Background(), fw, q)
	if err != nil || got.Unknown.Empty() {
		t.Fatal("unresolved allocation evidence was dropped", got, err)
	}
}

func TestPacketEasyIPUsesKnownEgressAndDoesNotSkipFirstMatchingRule(t *testing.T) {
	raw := strings.Replace(basic, "return\n", `nat-policy
 rule name easy
  source-zone trust
  destination-zone untrust
  egress-interface GigabitEthernet1/0/2
  action source-nat easy-ip
#
`, 1)
	q := policy.PacketRequest{Request: policy.Request{FromZone: "trust", Traffic: traffic(t, "192.0.2.10/32", "203.0.113.10/32", 6, 1000, 443)}}
	got, err := (policy.Engine{}).QueryPacket(context.Background(), parse(t, raw), q)
	if err != nil || !got.Complete || len(got.Paths) != 1 || got.Paths[0].NAT.Translated.Boxes()[0].Source.First.String() != "198.51.100.1" || !got.Paths[0].NAT.PossibleAllocation {
		t.Fatal(got, err)
	}
	noRoute := strings.Replace(raw, "ip route-static 0.0.0.0 0 198.51.100.254 preference 70\n", "", 1)
	got, err = (policy.Engine{}).QueryPacket(context.Background(), parse(t, noRoute), q)
	if err != nil || got.Complete || got.Unknown.Empty() {
		t.Fatal("missing route fell through", got, err)
	}
}
