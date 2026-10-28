package paloalto_test

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
	"github.com/gatework/firemon/vendors/paloalto"
)

func outboundRequest(t *testing.T) policy.Request {
	t.Helper()
	src, dst := netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("198.51.100.10")
	traffic, err := flow.NewTraffic(8, flow.Box{Source: flow.Range{First: src, Last: src}, Destination: flow.Range{First: dst, Last: dst},
		Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1234, High: 1234}, DestinationPort: flow.Interval{Low: 443, High: 443},
		ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	return policy.Request{FromZone: "inside", ToZone: "outside", Traffic: traffic}
}

func TestInterfaceNATRetainsSelectedHostThroughSnapshot(t *testing.T) {
	base, err := os.ReadFile("testdata/basic.cfg")
	if err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"uplink", "203.0.113.9", "203.0.113.9/24"} {
		t.Run(selector, func(t *testing.T) {
			raw := strings.Replace(string(base), "interface-address ip uplink", "interface-address ip "+selector, 1)
			raw += "set network interface ethernet ethernet1/2 layer3 ip 203.0.113.10/24\n"
			fw, err := paloalto.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"})
			if err != nil {
				t.Fatal(err)
			}
			if !fw.Complete() {
				t.Fatal(fw.Diagnostics())
			}
			var data bytes.Buffer
			if err := snapshot.Encode(&data, fw); err != nil {
				t.Fatal(err)
			}
			loaded, err := snapshot.Decode(&data, snapshot.DefaultMaxBytes)
			if err != nil {
				t.Fatal(err)
			}
			for _, graph := range []*fm.Firewall{fw, loaded} {
				got, err := (policy.Engine{}).QueryNAT(context.Background(), graph, outboundRequest(t))
				if err != nil || !got.Complete || len(got.Relations) != 1 {
					t.Fatal(got, err)
				}
				relation := got.Relations[0]
				boxes := relation.Translated.Boxes()
				want := netip.MustParseAddr("203.0.113.9")
				if len(boxes) != 1 || boxes[0].Source != (flow.Range{First: want, Last: want}) || relation.Exact || !relation.PossibleAllocation {
					t.Fatal("selected interface host expanded", boxes, relation.Exact, relation.PossibleAllocation)
				}
				packet, err := (policy.Engine{}).QueryPacket(context.Background(), graph, policy.PacketRequest{Request: outboundRequest(t), VRF: "default"})
				if err != nil || !packet.Complete || len(packet.Paths) != 1 {
					t.Fatal("packet path lost selected allocation", packet, err)
				}
				packetBoxes := packet.Paths[0].NAT.Translated.Boxes()
				if len(packetBoxes) != 1 || packetBoxes[0].Source != (flow.Range{First: want, Last: want}) {
					t.Fatal("packet path widened source", packetBoxes)
				}
			}
		})
	}
}

func TestXMLInterfaceNATUsesTheSelectedAddressObjectHost(t *testing.T) {
	raw := `<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/2"><layer3><ip><entry name="uplink"/><entry name="203.0.113.10/24"/></ip></layer3></entry></ethernet></interface></network><vsys><entry name="vsys1"><address><entry name="uplink"><ip-netmask>203.0.113.9/24</ip-netmask></entry></address><rulebase><nat><rules><entry name="outbound"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><service>any</service><source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/2</interface><ip>uplink</ip></interface-address></dynamic-ip-and-port></source-translation></entry></rules></nat></rulebase></entry></vsys></entry></devices></config>`
	fw, err := paloalto.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"})
	if err != nil || !fw.Complete() {
		t.Fatal(fw, err)
	}
	got, err := (policy.Engine{}).QueryNAT(context.Background(), fw, outboundRequest(t))
	if err != nil || !got.Complete || len(got.Relations) != 1 {
		t.Fatal(got, err)
	}
	boxes := got.Relations[0].Translated.Boxes()
	if len(boxes) != 1 || boxes[0].Source.First.String() != "203.0.113.9" || boxes[0].Source.Last.String() != "203.0.113.9" {
		t.Fatal("XML selected host expanded", boxes)
	}
}

func TestInterfaceNATRejectsUnassignedOrAmbiguousSelection(t *testing.T) {
	base, err := os.ReadFile("testdata/basic.cfg")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(string(base), "interface-address ip uplink", "interface-address ip 203.0.113.99", 1),
		strings.Replace(string(base), "interface-address ip uplink", "interface-address ip office", 1),
		strings.Replace(string(base), "set rulebase nat rules outbound source-translation dynamic-ip-and-port interface-address ip uplink\n", "", 1) + "set network interface ethernet ethernet1/2 layer3 ip 203.0.113.10/24\n",
	} {
		fw, err := paloalto.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"})
		if err != nil {
			t.Fatal(err)
		}
		if fw.Complete() {
			t.Fatal("unassigned or ambiguous selector accepted")
		}
		got, err := (policy.Engine{}).QueryNAT(context.Background(), fw, outboundRequest(t))
		if err == nil && (got.Complete || got.Unknown.Empty() || len(got.Relations) != 0) {
			t.Fatal("invalid interface selection became usable allocation", got)
		}
	}
}
