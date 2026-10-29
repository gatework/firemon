package paloalto_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors/paloalto"
)

func TestNativeXMLAndSetHaveSameGraphAndRetainOriginalXMLEvidence(t *testing.T) {
	xml := `<response status="success"><result><config version="10.2.0"><shared><address><entry name="client"><ip-netmask>192.0.2.100/32</ip-netmask></entry></address></shared><devices><entry name="localhost.localdomain"><network><virtual-router><entry name="default"><interface><member>ethernet1/1</member></interface><routing-table><ip><static-route><entry name="default"><destination>0.0.0.0/0</destination><nexthop><ip-address>203.0.113.1</ip-address></nexthop></entry></static-route></ip></routing-table></entry></virtual-router><interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.9/24"/></ip></layer3></entry></ethernet></interface></network><vsys><entry name="vsys1"><address><entry name="client"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address><zone><entry name="outside"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone><rulebase><security><rules><entry name="allow-web" uuid="test-native-id"><from><member>any</member></from><to><member>outside</member></to><source><member>client</member></source><destination><member>any</member></destination><service><member>service-https</member></service><application><member>any</member></application><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config></result></response>`
	set := "set shared address client ip-netmask 192.0.2.100/32\nset address client ip-netmask 192.0.2.10/32\nset zone outside network layer3 ethernet1/1\nset network virtual-router default interface ethernet1/1\nset network virtual-router default routing-table ip static-route default destination 0.0.0.0/0\nset network virtual-router default routing-table ip static-route default nexthop ip-address 203.0.113.1\nset network interface ethernet ethernet1/1 layer3 ip 203.0.113.9/24\nset rulebase security rules allow-web from any\nset rulebase security rules allow-web to outside\nset rulebase security rules allow-web source client\nset rulebase security rules allow-web destination any\nset rulebase security rules allow-web service service-https\nset rulebase security rules allow-web application any\nset rulebase security rules allow-web action allow\n"
	parse := func(raw string) *fm.Firewall {
		t.Helper()
		fw, err := paloalto.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"})
		if err != nil {
			t.Fatal(err)
		}
		if !fw.Complete() {
			t.Fatal(fw.Diagnostics())
		}
		return fw
	}
	fw, want := parse(xml), parse(set)
	if fw.SemanticDigest() != want.SemanticDigest() {
		t.Fatal("XML native paths changed graph semantics")
	}
	if fw.Export().Raw != xml || routeFor(t, fw, "default", "default").Interface() != fw.Interface("ethernet1/1") {
		t.Fatal("source or staged route binding lost")
	}
	spans := fw.Address("client").Record().Spans
	if len(spans) == 0 || spans[0].EndByte <= spans[0].StartByte || !strings.Contains(xml[spans[0].StartByte:spans[0].EndByte], "192.0.2.10") {
		t.Fatal("object lacks native byte provenance", spans)
	}
	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, fw); err != nil {
		t.Fatal(err)
	}
	restored, err := snapshot.Decode(&buf, snapshot.DefaultMaxBytes)
	if err != nil || restored.Export().Raw != xml || routeFor(t, restored, "default", "default").Interface() != restored.Interface("ethernet1/1") {
		t.Fatal("XML evidence or graph identity lost in snapshot", err)
	}
}

func TestUnknownXMLOnSameLineAndUnknownAttributesRemainPending(t *testing.T) {
	for _, unknown := range []string{`<opaque><address><entry name="fake"><ip-netmask>198.51.100.1/32</ip-netmask></entry></address></opaque>`, `<address><entry name="hidden" negate="yes"><ip-netmask>198.51.100.1/32</ip-netmask></entry></address>`} {
		raw := `<config><shared><address><entry name="safe"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address>` + unknown + `</shared></config>`
		fw, err := paloalto.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"})
		if err != nil {
			t.Fatal(err)
		}
		if fw.Complete() || fw.Address("safe") == nil || fw.Address("fake") != nil {
			t.Fatal("unknown native scope swallowed or escaped", fw.Diagnostics())
		}
		found := false
		for _, e := range fw.Export().Evidence {
			if e.State == fm.Pending && e.Span.EndByte > e.Span.StartByte {
				found = true
			}
		}
		if !found {
			t.Fatal("unknown byte evidence lost")
		}
	}
}

func TestXMLRejectsWrongRootFailedResponseAndAmbiguousDeviceContainers(t *testing.T) {
	for _, raw := range []string{`<response status="error"><result><config/></result></response>`, `<wrapper><config/></wrapper>`, `<config><devices><entry name="one"/><entry name="two"/></devices></config>`, `<config><shared><address><entry><ip-netmask>192.0.2.1</ip-netmask></entry></address></shared></config>`, `<config xmlns="urn:unknown"><shared/></config>`} {
		if _, err := paloalto.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"}); err == nil {
			t.Fatal("invalid native XML accepted", raw)
		}
	}
}
