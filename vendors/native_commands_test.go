package vendors_test

import (
	"bytes"
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNativeCreationRenderers(t *testing.T) {
	for _, name := range []string{"hillstone", "srx", "asa", "netscreen", "fortinet", "huawei"} {
		t.Run(name, func(t *testing.T) {
			r, err := vendors.Renderer(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := r.(plan.NativeRenderer); !ok {
				t.Fatal("native creation renderer missing")
			}
		})
	}
}

// The native capture is authored independently of renderer output. It is never
// produced by executing commands or applying graph edits to the expected graph.
func nativeDelta(before, after *fm.Firewall) plan.NativeChanges {
	c := plan.NativeChanges{}
	for _, r := range after.Rules() {
		if before.Rule(r.ID()) == nil && !r.Builtin() {
			v := r.Record()
			c.Additions.Rules = append(c.Additions.Rules, v)
			c.Rules = append(c.Rules, plan.Change{Kind: plan.CreateRule, Rule: v.ID, Sources: v.Match.Sources, Destinations: v.Match.Destinations, Services: v.Match.Services})
		}
	}
	for _, a := range after.Addresses() {
		if before.Address(a.ID()) == nil {
			c.Additions.Addresses = append(c.Additions.Addresses, a.Record())
		}
	}
	for _, s := range after.Services() {
		if before.Service(s.ID()) == nil {
			c.Additions.Services = append(c.Additions.Services, s.Record())
		}
	}
	for _, n := range after.StaticNATs() {
		if before.StaticNAT(n.ID()) == nil {
			c.Additions.StaticNATs = append(c.Additions.StaticNATs, n.Record())
		}
	}
	for _, n := range after.DynamicNATs() {
		if before.DynamicNAT(n.ID()) == nil {
			c.Additions.DynamicNATs = append(c.Additions.DynamicNATs, n.Record())
		}
	}
	for _, p := range after.NATPools() {
		if before.NATPool(p.ID()) == nil {
			c.Additions.NATPools = append(c.Additions.NATPools, p.Record())
		}
	}
	return c
}
func nativeParse(t *testing.T, v, version, raw string) *fm.Firewall {
	t.Helper()
	f, e := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic-native", Vendor: v, Software: version})
	if e != nil {
		t.Fatal(e)
	}
	if !f.Complete() {
		t.Fatal("incomplete native capture", f.Diagnostics())
	}
	return f
}
func TestNativeCreationCaptures(t *testing.T) {
	for _, tc := range nativeCases() {
		t.Run(tc.name, func(t *testing.T) {
			before := nativeParse(t, tc.vendor, tc.version, tc.before)
			after := nativeParse(t, tc.vendor, tc.version, tc.before+tc.after)
			c := nativeDelta(before, after)
			r, _ := vendors.Renderer(tc.vendor)
			commands, err := r.(plan.NativeRenderer).RenderNative(t.Context(), before, after, c)
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(commands, "\n")
			pos := 0
			for _, want := range tc.commands {
				idx := strings.Index(joined[pos:], want)
				if idx < 0 {
					t.Fatalf("missing/incorrect command order %q:\n%s", want, joined)
				}
				pos += idx + len(want)
			}
			var buf bytes.Buffer
			if err := snapshot.Encode(&buf, after); err != nil {
				t.Fatal(err)
			}
			restored, err := snapshot.Decode(&buf, snapshot.DefaultMaxBytes)
			if err != nil || restored.SemanticDigest() != after.SemanticDigest() {
				t.Fatal("snapshot", err)
			}
			q := policy.Request{Scope: tc.scope, FromZone: fm.ID(tc.from), ToZone: fm.ID(tc.to), EgressInterface: fm.ID(tc.egress), Traffic: nativeTraffic(t, tc.src, tc.dst, tc.port)}
			got, err := (policy.Engine{}).QueryNAT(t.Context(), restored, q)
			if err != nil || !got.Complete || len(got.Relations) != 1 {
				t.Fatal(got, err)
			}
			rel := got.Relations[0]
			boxes := rel.Translated.Regions()
			if len(boxes) != 1 || boxes[0].Source.First.String() != tc.wantSrc || boxes[0].Destination.First.String() != tc.wantDst || boxes[0].DestinationPort.Low != tc.wantPort || rel.PossibleAllocation != tc.possible || rel.Exact == tc.possible {
				t.Fatalf("wrong native relation: %+v", rel)
			}
		})
	}
}
func nativeTraffic(t *testing.T, src, dst string, port uint16) flow.Traffic {
	t.Helper()
	s := netip.MustParseAddr(src)
	d := netip.MustParseAddr(dst)
	r, e := flow.NewTraffic(16, flow.TrafficRegion{Source: flow.AddressRange{First: s, Last: s}, Destination: flow.AddressRange{First: d, Last: d}, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 12345, High: 12345}, DestinationPort: flow.Interval{Low: port, High: port}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if e != nil {
		t.Fatal(e)
	}
	return r
}

type nativeCase struct {
	name, vendor, version, before, after, scope, from, to, egress, src, dst, wantSrc, wantDst string
	port, wantPort                                                                            uint16
	possible                                                                                  bool
	commands                                                                                  []string
}

func nativeCases() []nativeCase {
	stone := "zone inside\nexit\nzone outside\nexit\ninterface eth0\nzone inside\nip address 192.0.2.1/24\nexit\ninterface eth1\nzone outside\nip address 198.51.100.1/24\nexit\n"
	junos := "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\nset interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24\nset security zones security-zone inside interfaces ge-0/0/0.0\nset security zones security-zone outside interfaces ge-0/0/1.0\n"
	asa := "interface i\nnameif inside\nsecurity-level 100\nip address 192.0.2.1 255.255.255.0\n!\ninterface o\nnameif outside\nsecurity-level 0\nip address 198.51.100.1 255.255.255.0\n!\n"
	cases := []nativeCase{
		{name: "hillstone-bnat", vendor: "hillstone", version: "5.5R8", before: stone, after: "bnatrule id 7 virtual ip 203.0.113.10/32 real ip 192.0.2.10/32\n", src: "192.0.2.10", dst: "198.51.100.20", wantSrc: "203.0.113.10", wantDst: "198.51.100.20", commands: []string{"bnatrule id 7 virtual ip 203.0.113.10/32 real ip \"192.0.2.10/32\""}},
		{name: "hillstone-dnat", vendor: "hillstone", version: "5.5R8", before: stone, after: "dnatrule id 7 from any to 203.0.113.10/32 service any trans-to 192.0.2.10\n", src: "198.51.100.20", dst: "203.0.113.10", wantSrc: "198.51.100.20", wantDst: "192.0.2.10", commands: []string{"dnatrule id 7 from \"any\" to \"203.0.113.10/32\" service \"any\" trans-to 192.0.2.10"}},
		{name: "hillstone-pool-pat", vendor: "hillstone", version: "5.5R8", before: stone, after: "snatrule id 7 from 192.0.2.10/32 to any service any trans-to 203.0.113.10 mode dynamicport\n", src: "192.0.2.10", dst: "198.51.100.20", wantSrc: "203.0.113.10", wantDst: "198.51.100.20", possible: true, commands: []string{"snatrule id 7 from \"192.0.2.10/32\" to \"any\" service \"any\" trans-to 203.0.113.10 mode dynamicport"}},
		{name: "hillstone-interface-pat", vendor: "hillstone", version: "5.5R8", before: stone, after: "snatrule id 7 from 192.0.2.10/32 to any service any trans-to eif-ip mode dynamicport eif eth1\n", egress: "eth1", src: "192.0.2.10", dst: "198.51.100.20", wantSrc: "198.51.100.1", wantDst: "198.51.100.20", possible: true, commands: []string{"trans-to eif-ip mode dynamicport eif \"eth1\""}},
		{name: "srx-static", vendor: "srx", version: "21.4R3", before: junos, after: "set security nat static rule-set inbound from zone outside\nset security nat static rule-set inbound rule fixed match destination-address 203.0.113.10/32\nset security nat static rule-set inbound rule fixed then static-nat prefix 192.0.2.10/32\n", from: "outside", to: "inside", src: "198.51.100.20", dst: "203.0.113.10", wantSrc: "198.51.100.20", wantDst: "192.0.2.10", commands: []string{"set security nat static rule-set inbound from zone outside", "rule fixed match destination-address 203.0.113.10/32", "then static-nat prefix 192.0.2.10/32"}},
		{name: "srx-destination-pool", vendor: "srx", version: "21.4R3", before: junos, after: "set security nat destination pool backend address 192.0.2.10/32\nset security nat destination rule-set inbound from zone outside\nset security nat destination rule-set inbound rule fixed match destination-address 203.0.113.10/32\nset security nat destination rule-set inbound rule fixed then destination-nat pool backend\n", from: "outside", to: "inside", src: "198.51.100.20", dst: "203.0.113.10", wantSrc: "198.51.100.20", wantDst: "192.0.2.10", commands: []string{"set security nat destination pool backend address 192.0.2.10/32", "then destination-nat pool backend"}},
		{name: "srx-source-pat", vendor: "srx", version: "21.4R3", before: junos, after: "set security nat source pool outbound address 203.0.113.10/32\nset security nat source rule-set outbound from zone inside\nset security nat source rule-set outbound to zone outside\nset security nat source rule-set outbound rule hide match source-address 192.0.2.10/32\nset security nat source rule-set outbound rule hide then source-nat pool outbound\n", from: "inside", to: "outside", src: "192.0.2.10", dst: "198.51.100.20", wantSrc: "203.0.113.10", wantDst: "198.51.100.20", possible: true, commands: []string{"set security nat source pool outbound address 203.0.113.10/32", "rule hide match source-address 192.0.2.10/32", "then source-nat pool outbound"}},
		{name: "asa-object-static", vendor: "asa", version: "9.16(4)", before: asa, after: "object network server\nhost 192.0.2.10\nnat (inside,outside) static 203.0.113.10\n", from: "inside", to: "outside", src: "192.0.2.10", dst: "198.51.100.20", wantSrc: "203.0.113.10", wantDst: "198.51.100.20", commands: []string{"object network server", "nat (inside,outside) static 203.0.113.10"}},
		{name: "asa-object-source-pat", vendor: "asa", version: "9.16(4)", before: asa, after: "object network server\nhost 192.0.2.10\nnat (inside,outside) dynamic 203.0.113.10\n", from: "inside", to: "outside", src: "192.0.2.10", dst: "198.51.100.20", wantSrc: "203.0.113.10", wantDst: "198.51.100.20", possible: true, commands: []string{"object network server", "nat (inside,outside) dynamic 203.0.113.10"}},
	}

	screen := "set interface ethernet0/1 zone Trust\nset interface ethernet0/1 ip 192.0.2.1/24\nset interface ethernet0/2 zone Untrust\nset interface ethernet0/2 ip 198.51.100.1/24\nset service inside-https protocol tcp src-port 0-65535 dst-port 443-443\n"
	forti := "config system interface\nedit lan1\nset vdom root\nset ip 192.0.2.1 255.255.255.0\nnext\nedit wan1\nset vdom root\nset ip 198.51.100.1 255.255.255.0\nnext\nend\n"
	fortiOwner := "config firewall policy\nedit 1\nset name hide\nset srcintf lan1\nset dstintf wan1\nset srcaddr all\nset dstaddr all\nset action accept\nset schedule always\nset service ALL\nset logtraffic disable\n"
	usg := "firewall zone trust\n add interface GigabitEthernet1/0/1\n#\nfirewall zone untrust\n add interface GigabitEthernet1/0/2\n#\ninterface GigabitEthernet1/0/1\n ip address 192.0.2.1 24\n#\ninterface GigabitEthernet1/0/2\n ip address 198.51.100.1 24\n#\n"
	cases = append(cases, []nativeCase{
		{name: "netscreen-mip", vendor: "netscreen", version: "6.3.0", before: screen, after: "set interface ethernet0/2 mip 198.51.100.60 host 192.0.2.60 netmask 255.255.255.255 vrouter trust-vr\nset policy id 1 from Untrust to Trust Any MIP(198.51.100.60) ANY permit\nexit\n", from: "Untrust", to: "Trust", src: "203.0.113.20", dst: "198.51.100.60", wantSrc: "203.0.113.20", wantDst: "192.0.2.60", commands: []string{"set interface \"ethernet0/2\" mip 198.51.100.60 host 192.0.2.60 netmask 255.255.255.255 vrouter \"trust-vr\""}},
		{name: "netscreen-vip", vendor: "netscreen", version: "6.3.0", before: screen, after: "set interface ethernet0/2 vip 198.51.100.70 443 inside-https 192.0.2.70\nset policy id 1 from Untrust to Trust Any VIP(198.51.100.70) inside-https permit\nexit\n", from: "Untrust", to: "Trust", src: "203.0.113.20", dst: "198.51.100.70", wantSrc: "203.0.113.20", wantDst: "192.0.2.70", commands: []string{"set interface \"ethernet0/2\" vip 198.51.100.70 443 \"inside-https\" 192.0.2.70"}},
		{name: "netscreen-dip-owner", vendor: "netscreen", version: "6.3.0", before: screen, after: "set interface ethernet0/2 dip 4 198.51.100.100 198.51.100.103\nset policy id 1 from Trust to Untrust Any Any ANY nat src dip-id 4 permit\nexit\n", from: "Trust", to: "Untrust", src: "192.0.2.10", dst: "203.0.113.20", wantSrc: "198.51.100.100", wantDst: "203.0.113.20", possible: true, commands: []string{"set interface \"ethernet0/2\" dip 4 198.51.100.100 198.51.100.103", "nat src dip-id 4"}},
		{name: "netscreen-policy-dnat", vendor: "netscreen", version: "6.3.0", before: screen, after: "set address Trust public-web 198.51.100.80/32\nset policy id 1 from Untrust to Trust Any public-web inside-https nat dst ip 192.0.2.80 port 443 permit\nexit\n", from: "Untrust", to: "Trust", src: "203.0.113.20", dst: "198.51.100.80", wantSrc: "203.0.113.20", wantDst: "192.0.2.80", commands: []string{"nat dst ip 192.0.2.80 port 443"}},
		{name: "fortinet-vip", vendor: "fortinet", version: "7.2.8", before: forti, after: "config firewall vip\nedit web\nset extintf wan1\nset extip 198.51.100.20\nset mappedip 192.0.2.20\nnext\nend\nconfig firewall policy\nedit 1\nset name inbound\nset srcintf wan1\nset dstintf lan1\nset srcaddr all\nset dstaddr web\nset action accept\nset schedule always\nset service ALL\nset logtraffic disable\nnext\nend\n", scope: "root", from: "wan1", to: "lan1", src: "203.0.113.20", dst: "198.51.100.20", wantSrc: "203.0.113.20", wantDst: "192.0.2.20", commands: []string{"config firewall vip", "set extintf \"wan1\"", "config firewall policy", "set dstaddr \"web\""}},
		{name: "fortinet-port-forward", vendor: "fortinet", version: "7.2.8", before: forti, after: "config firewall vip\nedit web\nset extintf wan1\nset extip 198.51.100.20\nset mappedip 192.0.2.20\nset portforward enable\nset protocol tcp\nset extport 443\nset mappedport 443\nnext\nend\nconfig firewall policy\nedit 1\nset name inbound\nset srcintf wan1\nset dstintf lan1\nset srcaddr all\nset dstaddr web\nset action accept\nset schedule always\nset service ALL\nset logtraffic disable\nnext\nend\n", scope: "root", from: "wan1", to: "lan1", src: "203.0.113.20", dst: "198.51.100.20", wantSrc: "203.0.113.20", wantDst: "192.0.2.20", commands: []string{"set portforward enable", "set extport 443", "set mappedport 443", "config firewall policy"}},
		{name: "fortinet-source-pool", vendor: "fortinet", version: "7.2.8", before: forti, after: "config firewall ippool\nedit outbound\nset startip 198.51.100.100\nset endip 198.51.100.103\nnext\nend\n" + fortiOwner + "set nat enable\nset ippool enable\nset poolname outbound\nnext\nend\n", scope: "root", from: "lan1", to: "wan1", src: "192.0.2.10", dst: "203.0.113.20", wantSrc: "198.51.100.100", wantDst: "203.0.113.20", possible: true, commands: []string{"config firewall ippool", "config firewall policy", "set nat enable", "set ippool enable", "set poolname \"outbound\""}},
		{name: "fortinet-interface-pat", vendor: "fortinet", version: "7.2.8", before: forti, after: fortiOwner + "set nat enable\nnext\nend\n", scope: "root", from: "lan1", to: "wan1", src: "192.0.2.10", dst: "203.0.113.20", wantSrc: "198.51.100.1", wantDst: "203.0.113.20", possible: true, commands: []string{"config firewall policy", "set nat enable"}},
		{name: "huawei-server-map", vendor: "huawei", version: "V500R005", before: usg, after: "nat server fixed zone untrust global 198.51.100.50 inside 192.0.2.50 no-reverse\n", from: "untrust", to: "trust", src: "203.0.113.20", dst: "198.51.100.50", wantSrc: "203.0.113.20", wantDst: "192.0.2.50", commands: []string{"nat server \"fixed\" zone \"untrust\" global 198.51.100.50 inside 192.0.2.50"}},
		{name: "huawei-source-pool", vendor: "huawei", version: "V500R005", before: usg, after: "nat address-group outbound\n mode pat\n section 0 198.51.100.100 198.51.100.103\n#\nnat-policy\n rule name hide\n  source-zone trust\n  destination-zone untrust\n  source-address 192.0.2.10 mask 32\n  action source-nat address-group outbound\n#\n", from: "trust", to: "untrust", src: "192.0.2.10", dst: "203.0.113.20", wantSrc: "198.51.100.100", wantDst: "203.0.113.20", possible: true, commands: []string{"nat address-group \"outbound\"", "mode pat", "section 0 198.51.100.100 198.51.100.103", "nat-policy", "action source-nat address-group \"outbound\""}},
		{name: "huawei-destination-pool", vendor: "huawei", version: "V500R005", before: usg, after: "destination-nat address-group backend\n section 0 192.0.2.20\n#\nnat-policy\n rule name incoming\n  source-zone untrust\n  destination-address 198.51.100.70 mask 32\n  action destination-nat address-group backend\n#\n", from: "untrust", to: "trust", src: "203.0.113.20", dst: "198.51.100.70", wantSrc: "203.0.113.20", wantDst: "192.0.2.20", commands: []string{"destination-nat address-group \"backend\"", "nat-policy", "action destination-nat address-group \"backend\""}},
	}...)

	for i := range cases {
		cases[i].port = 443
		cases[i].wantPort = 443
	}
	return cases
}

func TestNativeCreationPlanProofAndReadback(t *testing.T) {
	for _, tc := range nativeCases() {
		t.Run(tc.name, func(t *testing.T) {
			before, after, planner, input, baseline := nativePlanFixture(t, tc)
			result, err := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{input})
			if err != nil || result.Plan == nil {
				t.Fatalf("plan err=%v result=%+v", err, result)
			}
			p := result.Plan
			receipt, err := p.Verify(t.Context(), after)
			if err != nil {
				t.Fatal("independent readback", err)
			}
			if len(receipt.CreatedIDs()) == 0 {
				t.Fatal("missing typed identities")
			}
			again, err := planner.PlanNativeBatch(t.Context(), before, p.NativeInputs())
			if err != nil || again.Plan == nil || again.Plan.Digest() != p.Digest() {
				t.Fatal("reconstruction drift", err)
			}
			// A changed separately parsed native target must never match an approved plan.
			wrong := strings.Replace(tc.after, tc.wantDst, "192.0.2.222", 1)
			if wrong == tc.after {
				wrong = strings.Replace(tc.after, tc.wantSrc, "203.0.113.222", 1)
			}
			if wrong != tc.after {
				observed, e := (vendors.Parser{}).Parse(t.Context(), config.Source{Text: baseline + wrong, Complete: true}, fm.Metadata{Device: "synthetic-native", Vendor: tc.vendor, Software: tc.version})
				if e == nil {
					if _, e = p.Verify(t.Context(), observed); e == nil {
						t.Fatal("malformed native readback accepted")
					}
				}
			}
		})
	}
}

func nativePlanFixture(t *testing.T, tc nativeCase) (*fm.Firewall, *fm.Firewall, plan.Planner, plan.NativeRequest, string) {
	t.Helper()
	baseline := tc.before
	switch tc.vendor {
	case "hillstone":
		baseline += "policy-global\nrule id 100\nsrc-addr any\ndst-addr any\nservice any\naction permit\nexit\nexit\n"
	case "srx":
		for _, zones := range [][2]string{{"inside", "outside"}, {"outside", "inside"}} {
			p := "set security policies from-zone " + zones[0] + " to-zone " + zones[1] + " policy existing "
			baseline += p + "match source-address any-ipv4\n" + p + "match destination-address any-ipv4\n" + p + "match application any\n" + p + "then permit\n"
		}
	case "asa":
		baseline += "access-list IN extended permit ip any4 any4\naccess-list OUT extended permit ip any4 any4\naccess-group IN in interface inside\naccess-group OUT in interface outside\n"
	case "huawei":
		baseline += "security-policy\n rule name existing\n  action permit\n#\n"
	}
	before := nativeParse(t, tc.vendor, tc.version, baseline)
	after := nativeParse(t, tc.vendor, tc.version, baseline+tc.after)
	c := nativeDelta(before, after)

	engine := policy.Engine{}
	// Enumerate complete native relation domains from the independently authored
	// capture. Sample assertions in TestNativeCreationCaptures independently fix
	// expected address/port direction and allocation semantics for each form.
	contexts, err := engine.NATContexts(t.Context(), time.Time{}, before, after)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := flow.AllTraffic(4096)
	var intents []policy.NATIntent
	for _, q := range contexts {
		q.Traffic = all
		r, e := engine.QueryNAT(t.Context(), after, q)
		if e != nil {
			t.Fatal(e)
		}
		if !r.Complete {
			t.Fatalf("native domain incomplete scope=%q from=%q to=%q egress=%q", q.Scope, q.FromZone, q.ToZone, q.EgressInterface)
		}
		for _, rel := range r.Relations {
			q.Traffic = rel.Original
			intents = append(intents, policy.NATIntent{Request: q, Steps: rel.Steps})
		}
	}
	if len(intents) == 0 {
		t.Fatal("missing native effect")
	}
	proof, err := engine.ProveNATEffects(t.Context(), before, after, intents)
	if err != nil || !proof.OutsidePreserved || !proof.IntentSatisfied {
		t.Fatal("effect proof", proof, err)
	}
	q := policy.Request{Scope: tc.scope, FromZone: fm.ID(tc.from), ToZone: fm.ID(tc.to), EgressInterface: fm.ID(tc.egress), Traffic: nativeTraffic(t, tc.src, tc.dst, tc.port)}
	if len(c.Rules) > 0 {
		q.Traffic = all
		result, e := engine.Query(t.Context(), after, q)
		if e != nil {
			t.Fatal(e)
		}
		q.Traffic = result.Allowed
	}
	if tc.vendor == "asa" {
		q.RuleSet = "IN"
	}
	renderer, _ := vendors.Renderer(tc.vendor)
	planner := plan.Planner{Renderer: renderer, NativeRenderer: renderer.(plan.NativeRenderer)}
	for i := range c.Additions.Rules {
		c.Additions.Rules[i].Position = -len(c.Additions.Rules) + i
	}
	input := plan.NativeRequest{Request: q, Additions: c.Additions, NAT: intents, Sources: []string{tc.name}}
	return before, after, planner, input, baseline
}

func nativeCaseNamed(t *testing.T, name string) nativeCase {
	t.Helper()
	for _, tc := range nativeCases() {
		if tc.name == name {
			return tc
		}
	}
	t.Fatal("missing case", name)
	return nativeCase{}
}

func TestNativeCreationRejectsMalformedOwnershipAndNamespace(t *testing.T) {
	for _, tc := range []struct {
		name, fixture string
		change        func(*fm.Data)
	}{
		{"vip-source-parent", "fortinet-vip", func(d *fm.Data) { d.StaticNATs[1].SourceVIP.ID = "missing" }},
		{"vip-source-mapping", "fortinet-vip", func(d *fm.Data) { d.StaticNATs[1].Source[0].Translated = d.StaticNATs[1].Source[0].Original }},
		{"vip-source-match", "fortinet-vip", func(d *fm.Data) { d.StaticNATs[1].Match.AnyToZone = true; d.StaticNATs[1].Match.ToZones = nil }},
		{"vip-source-stage", "fortinet-vip", func(d *fm.Data) { d.StaticNATs[1].Order.Stage = 99 }},
		{"vip-source-section", "fortinet-vip", func(d *fm.Data) { d.StaticNATs[1].Order.Section = "arbitrary" }},
		{"vip-parent-address", "fortinet-vip", func(d *fm.Data) { d.Addresses[0].VIP.ID = "missing" }},
		{"vip-shared-static-dynamic-namespace", "fortinet-vip", func(d *fm.Data) {
			n := d.StaticNATs[0]
			d.DynamicNATs = append(d.DynamicNATs, fm.DynamicNATRecord{Object: fm.Object{ID: "duplicate", Name: n.Name, Scope: n.Scope}, Match: n.Match, Order: n.Order, Destination: n.Destination, SourceMode: fm.NoTranslation, DestinationMode: fm.StaticIP})
		}},
		{"vip-arbitrary-namespace-escape", "fortinet-vip", func(d *fm.Data) {
			n := d.StaticNATs[0]
			n.ID = "duplicate"
			n.Order.Stage = 99
			n.Order.Section = "arbitrary"
			d.StaticNATs = append(d.StaticNATs, n)
		}},
		{"asa-inline-owner", "asa-object-static", func(d *fm.Data) {
			for i := range d.Addresses {
				if d.Addresses[i].Name == "server" {
					d.Addresses[i].Inline = true
				}
			}
		}},
		{"screen-inline-declaration", "netscreen-policy-dnat", func(d *fm.Data) {
			for i := range d.Addresses {
				if d.Addresses[i].Name == "public-web" {
					d.Addresses[i].Inline = true
				}
			}
		}},
		{"inline-impostor", "huawei-source-pool", func(d *fm.Data) { d.Addresses[0].Name = "ordinary" }},
		{"inline-orphan", "huawei-source-pool", func(d *fm.Data) {
			a := d.Addresses[0]
			a.ID = "orphan"
			a.Name = "orphan"
			d.Addresses = append(d.Addresses, a)
		}},
		{"inline-pool", "huawei-source-pool", func(d *fm.Data) { d.NATPools[0].Inline = true }},
		{"bidirectional-server-map", "huawei-server-map", func(d *fm.Data) { d.StaticNATs[0].Bidirectional = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := nativeCaseNamed(t, tc.fixture)
			before := nativeParse(t, f.vendor, f.version, f.before)
			after := nativeParse(t, f.vendor, f.version, f.before+f.after)
			d := after.Export()
			tc.change(&d)
			malformed, err := fm.Seal(d)
			if err != nil {
				return
			}
			renderer, _ := vendors.Renderer(f.vendor)
			commands, err := renderer.(plan.NativeRenderer).RenderNative(t.Context(), before, malformed, nativeDelta(before, malformed))
			if err == nil || len(commands) != 0 {
				t.Fatalf("unsafe native representation emitted: %v %v", commands, err)
			}
		})
	}
}

func TestNativeCreationReadbackAndOwnershipGuards(t *testing.T) {
	for _, name := range []string{"fortinet-vip", "huawei-source-pool"} {
		t.Run(name, func(t *testing.T) {
			before, after, planner, input, _ := nativePlanFixture(t, nativeCaseNamed(t, name))
			result, err := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{input})
			if err != nil || result.Plan == nil {
				t.Fatal(result, err)
			}
			p := result.Plan
			t.Run("unrequested", func(t *testing.T) {
				orphan := input.Clone()
				orphan.NAT = nil
				got, err := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{orphan})
				if err == nil && got.Plan != nil {
					t.Fatal("unrequested NAT accepted")
				}
			})
			t.Run("outside-intent", func(t *testing.T) {
				narrow := input.Clone()
				narrow.NAT = narrow.NAT[:1]
				narrow.NAT[0].Request.Traffic = nativeTraffic(t, "203.0.113.20", "198.51.100.20", 443)
				got, err := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{narrow})
				if err == nil && got.Plan != nil {
					t.Fatal("outside NAT effect accepted")
				}
			})
			t.Run("ambiguous-readback", func(t *testing.T) {
				d := after.Export()
				if len(d.StaticNATs) > 0 {
					n := d.StaticNATs[0]
					n.ID = "duplicate"
					d.StaticNATs = append(d.StaticNATs, n)
				} else {
					n := d.DynamicNATs[0]
					n.ID = "duplicate"
					d.DynamicNATs = append(d.DynamicNATs, n)
				}
				bad, err := fm.Seal(d)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = p.Verify(t.Context(), bad); err == nil {
					t.Fatal("ambiguous readback accepted")
				}
			})
			t.Run("missing-readback", func(t *testing.T) {
				if _, err := p.Verify(t.Context(), before); err == nil {
					t.Fatal("missing native readback accepted")
				}
			})
			t.Run("cancel", func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				got, err := planner.PlanNativeBatch(ctx, before, []plan.NativeRequest{input})
				if !errors.Is(err, context.Canceled) || got.Plan != nil {
					t.Fatal(got, err)
				}
			})
			t.Run("budget", func(t *testing.T) {
				limited := planner
				limited.Engine.Limits = policy.Limits{MaxVisits: 1}
				got, err := limited.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{input})
				if !errors.Is(err, policy.ErrBudget) || got.Plan != nil {
					t.Fatal(got, err)
				}
			})
			if name == "fortinet-vip" {
				d := after.Export()
				for i := range d.StaticNATs {
					d.StaticNATs[i].ID = "allocated:" + d.StaticNATs[i].ID
					if d.StaticNATs[i].SourceVIP.ID != "" {
						d.StaticNATs[i].SourceVIP.ID = "allocated:" + d.StaticNATs[i].SourceVIP.ID
					}
				}
				for i := range d.Addresses {
					if d.Addresses[i].VIP.ID == "" {
						continue
					}
					d.Addresses[i].ID = "allocated:" + d.Addresses[i].ID
					d.Addresses[i].VIP.ID = "allocated:" + d.Addresses[i].VIP.ID
				}
				for i := range d.Rules {
					for j := range d.Rules[i].Match.Destinations {
						if !strings.HasPrefix(string(d.Rules[i].Match.Destinations[j].ID), "vip:") {
							continue
						}
						d.Rules[i].Match.Destinations[j].ID = "allocated:" + d.Rules[i].Match.Destinations[j].ID
					}
				}
				allocated, err := fm.Seal(d)
				if err != nil {
					t.Fatal(err)
				}
				receipt, err := p.Verify(t.Context(), allocated)
				if err != nil {
					t.Fatal("allocated VIP identities", err)
				}
				for key, id := range receipt.CreatedIDs() {
					if key.Kind == plan.NativeStaticNAT && id != "allocated:"+key.ID {
						t.Fatal("lost projection identity", key, id)
					}
				}
			}
		})
	}
}

func TestNativeCreationVersionGates(t *testing.T) {
	for _, name := range []string{"hillstone-interface-pat", "asa-object-static", "huawei-server-map"} {
		t.Run(name, func(t *testing.T) {
			tc := nativeCaseNamed(t, name)
			before := nativeParse(t, tc.vendor, "unknown", tc.before)
			after := nativeParse(t, tc.vendor, "unknown", tc.before+tc.after)
			r, _ := vendors.Renderer(tc.vendor)
			if commands, err := r.(plan.NativeRenderer).RenderNative(t.Context(), before, after, nativeDelta(before, after)); err == nil || len(commands) != 0 {
				t.Fatal("unknown firmware emitted", commands, err)
			}
		})
	}
}

func TestFortinetNATContextApplicableEgress(t *testing.T) {
	tc := nativeCaseNamed(t, "fortinet-interface-pat")
	base := nativeParse(t, tc.vendor, tc.version, tc.before)
	for _, mutation := range []string{"complete", "multiple", "missing", "disabled", "invalid", "other-scope"} {
		t.Run(mutation, func(t *testing.T) {
			d := base.Export()
			var wi int
			for i := range d.Interfaces {
				if d.Interfaces[i].ID == "wan1" {
					wi = i
				}
			}
			switch mutation {
			case "multiple":
				n := d.Interfaces[wi]
				n.ID = "wan2"
				n.Name = "wan2"
				d.Interfaces = append(d.Interfaces, n)
			case "missing":
				d.Interfaces = append(d.Interfaces[:wi], d.Interfaces[wi+1:]...)
			case "disabled":
				d.Interfaces[wi].Disabled = true
			case "invalid":
				d.Interfaces[wi].Unsupported = []string{"unknown"}
			case "other-scope":
				d.Interfaces[wi].Scope = "other"
			}
			fw, err := fm.Seal(d)
			if err != nil {
				t.Fatal(err)
			}
			contexts, err := (policy.Engine{}).NATContexts(t.Context(), time.Time{}, fw)
			if err != nil && (mutation == "missing" || mutation == "invalid" || mutation == "other-scope") {
				if !errors.Is(err, policy.ErrNotEquivalent) {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			seen := map[fm.ID]bool{}
			for _, q := range contexts {
				if q.Scope == "root" && q.ToZone == "wan1" {
					seen[q.EgressInterface] = true
				}
			}
			want := map[fm.ID]bool{"": true}
			if mutation == "complete" {
				want = map[fm.ID]bool{"wan1": true}
			}
			if mutation == "multiple" {
				want = map[fm.ID]bool{"wan1": true, "wan2": true}
			}
			if !reflect.DeepEqual(seen, want) {
				t.Fatalf("applicable domain %v want %v", seen, want)
			}
			again, err := (policy.Engine{}).NATContexts(t.Context(), time.Time{}, fw)
			if err != nil || !reflect.DeepEqual(contexts, again) {
				t.Fatal("nondeterministic contexts", err)
			}
			if _, err := (policy.Engine{Limits: policy.Limits{MaxCombinations: 1}}).NATContexts(t.Context(), time.Time{}, fw); !errors.Is(err, policy.ErrBudget) {
				t.Fatal("context capacity", err)
			}
		})
	}
}

func TestStoneOSNativeCreationWireProofAndReadback(t *testing.T) {
	for _, tc := range nativeCases() {
		if tc.vendor != "hillstone" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			before, after, planner, input, _ := nativePlanFixture(t, tc)
			input.Request.FromZone = "inside"
			input.Request.ToZone = "outside"
			if tc.name == "hillstone-dnat" {
				input.Request.FromZone = "outside"
				input.Request.ToZone = "inside"
			}
			packet := policy.PacketRequest{Request: input.Request}
			packet.ToZone = ""
			packet.EgressInterface = ""
			input.Packet = &packet
			got, err := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{input})
			if err != nil || got.Plan == nil {
				t.Fatal("wire native plan", got, err)
			}
			if len(got.Plan.PacketProofs()) != 1 {
				t.Fatal("missing packet proof")
			}
			if _, err = got.Plan.Verify(t.Context(), after); err != nil {
				t.Fatal("wire readback", err)
			}
		})
	}
}

func TestASAObjectNativeInsertionPreservesDerivedOrder(t *testing.T) {
	tc := nativeCaseNamed(t, "asa-object-static")
	tc.before += "object network existing\nhost 192.0.2.90\nnat (inside,outside) static 203.0.113.90\n!\n"
	before, after, planner, input, _ := nativePlanFixture(t, tc)
	// The request proposes an insertion before the existing auto-NAT entry;
	// native readback independently supplies its derived rank.
	input.Additions.StaticNATs[0].Order.Position = -1
	got, err := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{input})
	if err != nil || got.Plan == nil {
		t.Fatal(got, err)
	}
	if _, err = got.Plan.Verify(t.Context(), after); err != nil {
		t.Fatal(err)
	}
	seq := after.NATSequence()
	if len(seq) != 2 || seq[0].ID != "auto:server" || seq[1].ID != "auto:existing" {
		t.Fatal("incorrect derived order", seq)
	}
}

func TestHuaweiNativeInlineServiceOwnership(t *testing.T) {
	tc := nativeCaseNamed(t, "huawei-source-pool")
	tc.after = strings.Replace(tc.after, "  action source-nat", "  service protocol tcp source-port 12345 destination-port 443\n  action source-nat", 1)
	before, after, planner, input, _ := nativePlanFixture(t, tc)
	if len(input.Additions.Services) != 1 || !input.Additions.Services[0].Inline {
		t.Fatal("fixture did not exercise parent-owned inline service")
	}
	got, err := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{input})
	if err != nil || got.Plan == nil {
		t.Fatal(got, err)
	}
	if _, err = got.Plan.Verify(t.Context(), after); err != nil {
		t.Fatal(err)
	}
	t.Run("shared literals", func(t *testing.T) {
		_, block, ok := strings.Cut(tc.after, "nat-policy\n")
		if !ok {
			t.Fatal("missing NAT policy fixture")
		}
		block = strings.Replace(block, "rule name ", "rule name shared-", 1)
		base := nativeParse(t, tc.vendor, tc.version, tc.before)
		shared := nativeParse(t, tc.vendor, tc.version, tc.before+tc.after+"nat-policy\n"+block)
		delta := nativeDelta(base, shared)
		if len(delta.Additions.DynamicNATs) != 2 || len(delta.Additions.Services) != 1 || !delta.Additions.Services[0].Inline {
			t.Fatal("fixture must have two owners sharing one inline service")
		}
		renderer, _ := vendors.Renderer(tc.vendor)
		commands, err := renderer.(plan.NativeRenderer).RenderNative(t.Context(), base, shared, delta)
		if err != nil {
			t.Fatal(err)
		}
		if text := strings.Join(commands, "\n"); strings.Count(text, "service protocol tcp source-port 12345 destination-port 443") != 2 || strings.Contains(text, "ip service-set") {
			t.Fatalf("shared inline service must be emitted by both owners: %s", text)
		}
	})
	for _, kind := range []string{"identity", "orphan"} {
		t.Run(kind, func(t *testing.T) {
			bad := input.Clone()
			if kind == "identity" {
				bad.Additions.Services[0].Name = "impostor"
			} else {
				bad.Additions.DynamicNATs[0].Match.Services = nil
				bad.Additions.DynamicNATs[0].Match.AnyService = true
			}
			rejected, err := planner.PlanNativeBatch(t.Context(), before, []plan.NativeRequest{bad})
			if err == nil && rejected.Plan != nil {
				t.Fatal("inline service bypassed ownership", kind)
			}
		})
	}
}
