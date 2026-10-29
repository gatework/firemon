package netscreen_test

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
	"github.com/gatework/firemon/vendors/netscreen"
)

func parse(t *testing.T, raw string) *fm.Firewall {
	t.Helper()
	fw, err := netscreen.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fw"})
	if err != nil {
		t.Fatal(err)
	}
	return fw
}
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".set")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func traffic(t *testing.T, src, dst string, proto, sp, dp uint16) flow.Traffic {
	t.Helper()
	a, err := flow.PrefixRange(netip.MustParsePrefix(src))
	if err != nil {
		t.Fatal(err)
	}
	b, err := flow.PrefixRange(netip.MustParsePrefix(dst))
	if err != nil {
		t.Fatal(err)
	}
	out, err := flow.NewTraffic(32, flow.Box{Source: a, Destination: b, Protocol: flow.Interval{Low: proto, High: proto}, SourcePort: flow.Interval{Low: sp, High: sp}, DestinationPort: flow.Interval{Low: dp, High: dp}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestScopedAddressesPairedServicesAndOrderedRouteBinding(t *testing.T) {
	fw := parse(t, fixture(t, "basic"))
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	if len(fw.Interfaces()) != 2 || len(fw.Routes()) != 4 || len(fw.Rules()) != 4 {
		t.Fatal("missing objects", len(fw.Interfaces()), len(fw.Routes()), len(fw.Rules()))
	}
	inside := fw.Interface("ethernet0/1")
	if inside.Scope() != "blue-vr" || len(inside.Routes()) != 2 {
		t.Fatal("route binding", inside.Record(), inside.Routes())
	}
	for _, r := range fw.Routes() {
		if !r.Record().Direct && r.Interface() != inside {
			t.Fatal("cross-VRF next-hop binding", r.Record())
		}
	}
	r := fw.Rule("10").Record()
	if r.Name != "paired traffic" || r.LogStart != fm.Known || r.LogEnd != fm.Known {
		t.Fatal(r)
	}
	for _, tc := range []struct {
		proto, sp, dp uint16
		dst           string
		allow         bool
	}{
		{6, 1000, 443, "198.51.100.20/32", true}, {17, 2000, 53, "198.51.100.21/32", true},
		{6, 2000, 53, "198.51.100.20/32", false}, {17, 1000, 443, "198.51.100.20/32", false},
		{6, 1000, 443, "203.0.113.5/32", true}, {6, 1000, 443, "192.0.2.10/32", false},
	} {
		q := policy.Request{Traffic: traffic(t, "192.0.2.10/32", tc.dst, tc.proto, tc.sp, tc.dp), FromZone: "Trust", ToZone: "Untrust"}
		result, err := (policy.Engine{}).Query(context.Background(), fw, q)
		if err != nil || !result.Complete || result.Allowed.Empty() == tc.allow || !result.Unknown.Empty() || !result.Unmatched.Empty() {
			t.Fatal(tc, result, err)
		}
	}
	zero := fw.Service("zero").Record().Terms
	if len(zero) != 1 || zero[0].Protocol != (flow.Interval{}) {
		t.Fatal("protocol zero became wildcard", zero)
	}
	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, fw); err != nil {
		t.Fatal(err)
	}
	restored, err := snapshot.Decode(&buf, snapshot.DefaultMaxBytes)
	if err != nil || restored.SemanticDigest() != fw.SemanticDigest() {
		t.Fatal(err)
	}
	if restored.Interface("ethernet0/1").Routes()[0].Interface() != restored.Interface("ethernet0/1") {
		t.Fatal("lost shared reference")
	}
}

func TestUnknownScopesAndIncompleteConditionsCannotPermit(t *testing.T) {
	base := fixture(t, "basic")
	for _, extra := range []string{
		"set vsys tenant\nset interface hidden zone Trust\nset address Trust injected 203.0.113.9/32\nset policy id 90 from Trust to Untrust Any Any ANY permit\nexit\n",
		"set vrouter customer\nset address Trust injected 203.0.113.9/32\nexit\n",
		"set policy id 10\nset url filtering on\nset address Trust injected 203.0.113.9/32\nexit\n",
		"set service pair protocol tcp src-port 0-65535 dst-port 443-443 alg ftp\n",
		"set policy id 91 from Trust to Untrust Any Any ANY permit unknown-condition\nexit\n",
		"set policy id 10 from Trust to Untrust Any Any ANY permit\nexit\n",
	} {
		fw := parse(t, base+extra)
		if fw.Complete() {
			t.Fatal("unsupported context accepted", extra)
		}
		for _, a := range fw.Addresses() {
			if a.Name() == "injected" {
				t.Fatal("nested root syntax escaped its context", extra)
			}
		}
		if fw.Interface("hidden") != nil {
			t.Fatal("unknown vsys leaked interface")
		}
		q := policy.Request{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.20/32", 6, 1000, 443), FromZone: "Trust", ToZone: "Untrust"}
		r, err := (policy.Engine{}).Query(context.Background(), fw, q)
		if err != nil || !r.Allowed.Empty() || r.Unknown.Empty() {
			t.Fatal("unsupported became permit", extra, r, err)
		}
	}
}

func TestPolicyTopDisableAndIPv4Any(t *testing.T) {
	raw := fixture(t, "basic") + "set policy id 30 top from Trust to Untrust Any Any ANY deny\nexit\n"
	fw := parse(t, raw)
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	q := policy.Request{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.20/32", 6, 1000, 443), FromZone: "Trust", ToZone: "Untrust"}
	r, err := (policy.Engine{}).Query(context.Background(), fw, q)
	if err != nil || r.Denied.Empty() || r.Trace[0].Rule != "30" {
		t.Fatal(r, err)
	}
	fw = parse(t, raw+"set policy id 30 disable\nexit\n")
	r, err = (policy.Engine{}).Query(context.Background(), fw, q)
	if err != nil || r.Allowed.Empty() {
		t.Fatal(r, err)
	}
	fw = parse(t, strings.ReplaceAll(raw, "Any Any ANY deny", "Any Any ANY permit"))
	q.Traffic = traffic(t, "2001:db8::1/128", "2001:db8::2/128", 6, 1000, 443)
	r, err = (policy.Engine{}).Query(context.Background(), fw, q)
	if err != nil || !r.Allowed.Empty() {
		t.Fatal("IPv4 Any permitted IPv6", r, err)
	}
}

func TestIntrazoneBlockingControlsWhetherNativePoliciesAreConsulted(t *testing.T) {
	ctx := context.Background()
	raw := topology + "set policy id 1 from Trust to Trust Any Any ANY deny\nexit\n"
	q := policy.Request{Traffic: traffic(t, "192.0.2.10/32", "192.0.2.20/32", 6, 12345, 443), FromZone: "Trust", ToZone: "Trust"}
	for _, tc := range []struct {
		extra string
		allow bool
	}{{"", true}, {"set zone Trust block\n", false}, {"set zone Trust block\nunset zone Trust block\n", true}} {
		fw := parse(t, raw+tc.extra)
		if !fw.Complete() {
			t.Fatal(fw.Diagnostics())
		}
		r, err := (policy.Engine{}).Query(ctx, fw, q)
		if err != nil || !r.Complete || r.Allowed.Empty() == tc.allow {
			t.Fatal(tc, r, err)
		}
	}
	q.FromZone, q.ToZone = "Untrust", "Untrust"
	r, err := (policy.Engine{}).Query(ctx, parse(t, topology), q)
	if err != nil || r.Denied.Empty() {
		t.Fatal("Untrust default blocking lost", r, err)
	}
}
