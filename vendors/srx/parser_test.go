package srx_test

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
	"github.com/gatework/firemon/vendors/srx"
)

func parse(t *testing.T, raw string) *fm.Firewall {
	t.Helper()
	fw, err := srx.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "fw"})
	if err != nil {
		t.Fatal(err)
	}
	return fw
}
func fixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/basic.set")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func traffic(t *testing.T, src, dst string, proto, sp, dp uint16) flow.Traffic {
	t.Helper()
	a, _ := flow.PrefixRange(netip.MustParsePrefix(src))
	b, _ := flow.PrefixRange(netip.MustParsePrefix(dst))
	r, err := flow.NewTraffic(16, flow.Box{Source: a, Destination: b, Protocol: flow.Interval{Low: proto, High: proto}, SourcePort: flow.Interval{Low: sp, High: sp}, DestinationPort: flow.Interval{Low: dp, High: dp}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestScopedBooksTermPairsAndInterfaceBeforeRouteBinding(t *testing.T) {
	fw := parse(t, fixture(t))
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	if len(fw.Interfaces()) != 3 || len(fw.Routes()) != 4 || len(fw.Rules()) != 3 {
		t.Fatal("missing native objects", len(fw.Interfaces()), len(fw.Routes()), len(fw.Rules()))
	}
	iface := fw.Interface("ge-0/0/0.0")
	if iface == nil || iface.Record().Scope != "customer" || len(iface.Routes()) != 2 {
		t.Fatal("route not bound after interface pass", iface)
	}
	for _, route := range fw.Routes() {
		if !route.Record().Direct && route.Interface() != iface {
			t.Fatal("route bound outside routing instance", route.Record())
		}
	}
	rule := fw.Rules()[0]
	if rule.Record().Name != "permit-web" || rule.Record().LogEnd != fm.Known || rule.Record().LogStart != fm.Irrelevant {
		t.Fatal(rule.Record())
	}
	if fw.Rules()[0].Record().ID == fw.Rules()[1].Record().ID {
		t.Fatal("policy IDs collapsed across zone pairs")
	}
	for _, tc := range []struct {
		proto, sp, dp uint16
		allow         bool
	}{{6, 1000, 443, true}, {17, 2000, 53, true}, {6, 2000, 53, false}, {17, 1000, 443, false}} {
		q := policy.Request{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.20/32", tc.proto, tc.sp, tc.dp), FromZone: "inside", ToZone: "outside"}
		r, err := (policy.Engine{}).Query(context.Background(), fw, q)
		if err != nil || !r.Complete || r.Allowed.Empty() == tc.allow || !r.Unknown.Empty() || !r.Unmatched.Empty() {
			t.Fatal(tc, r, err)
		}
	}
	var buf bytes.Buffer
	if err := snapshot.Encode(&buf, fw); err != nil {
		t.Fatal(err)
	}
	restored, err := snapshot.Decode(&buf, snapshot.DefaultMaxBytes)
	if err != nil || restored.SemanticDigest() != fw.SemanticDigest() {
		t.Fatal(err)
	}
	if restored.Interface("ge-0/0/0.0").Routes()[0].Interface() != restored.Interface("ge-0/0/0.0") {
		t.Fatal("snapshot lost shared interface identity")
	}
	if restored.Zone("inside").Record().AddressScope != "book:internal" {
		t.Fatal("snapshot lost native address book attachment")
	}
}

func TestScopedUnknownsAndMalformedConditionsCannotPermit(t *testing.T) {
	for _, extra := range []string{
		"set groups sneaky security policies default-policy permit-all\nset apply-groups sneaky\n",
		"set security policies from-zone inside to-zone outside policy permit-web match source-identity any\n",
		"set applications application pair term tcp alg ftp\n",
		"deactivate security policies from-zone inside to-zone outside policy permit-web match source-address\n",
		"set security address-book conflicting attach zone inside\nset security address-book conflicting address host 203.0.113.10/32\n",
		"set security address-book internal address-set clients address-set nested\n",
	} {
		t.Run(extra, func(t *testing.T) {
			fw := parse(t, fixture(t)+extra)
			if fw.Complete() {
				t.Fatal("unsupported source was accepted")
			}
			r, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.20/32", 6, 1000, 443), FromZone: "inside", ToZone: "outside"})
			if err != nil || !r.Allowed.Empty() {
				t.Fatal(r, err)
			}
		})
	}
}

func TestDeactivatedPolicyAndIPv4AnyDoNotPermitIPv6(t *testing.T) {
	raw := fixture(t) + "deactivate security policies from-zone inside to-zone outside policy permit-web\n"
	fw := parse(t, raw)
	if !fw.Complete() || !fw.Rules()[0].Record().Disabled {
		t.Fatal(fw.Diagnostics())
	}
	r, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.20/32", 6, 1000, 443), FromZone: "inside", ToZone: "outside"})
	if err != nil || r.Denied.Empty() {
		t.Fatal(r, err)
	}
	fw = parse(t, strings.ReplaceAll(fixture(t), "then reject", "then permit"))
	r, err = (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: traffic(t, "2001:db8:1::10/128", "2001:db8:2::20/128", 6, 1000, 443), FromZone: "outside", ToZone: "inside"})
	if err != nil || !r.Allowed.Empty() || r.Denied.Empty() {
		t.Fatal(r, err)
	}
}

func TestAddressBookLookupRetainsGlobalFallbackAndBuiltinShadowing(t *testing.T) {
	raw := fixture(t) + "set security address-book global address any-ipv4 203.0.113.7/32\n"
	fw := parse(t, strings.ReplaceAll(raw, "then reject", "then permit"))
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	// Explicit native addresses shadow predefined names, including any-ipv4.
	r, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: traffic(t, "198.51.100.20/32", "192.0.2.10/32", 6, 1000, 443), FromZone: "outside", ToZone: "inside"})
	if err != nil || !r.Allowed.Empty() {
		t.Fatal("shadowed builtin became unrestricted", r, err)
	}
	if fw.Address("fallback") == nil || fw.Address("fallback").Record().Scope != "" {
		t.Fatal("global objects must have stable unscoped identities")
	}
	raw = strings.ReplaceAll(fixture(t), "match destination-address host", "match destination-address fallback")
	fw = parse(t, raw)
	r, err = (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: traffic(t, "192.0.2.10/32", "198.51.100.30/32", 6, 1000, 443), FromZone: "inside", ToZone: "outside"})
	if err != nil || r.Allowed.Empty() {
		t.Fatal("global fallback lost", r, err)
	}
}

func TestInvalidAddressBookAttachmentsAndUnalignedPrefixesRemainIncomplete(t *testing.T) {
	for _, extra := range []string{
		"set security address-book internal attach zone missing\n",
		"set security zones security-zone inside address-book address host 203.0.113.8/32\n",
		"set security address-book global address bad 203.0.113.5/24\n",
	} {
		fw := parse(t, fixture(t)+extra)
		if fw.Complete() {
			t.Fatal("invalid book context accepted", extra)
		}
	}
}

func TestUnusedAddressBookAttachmentParticipatesInSnapshotIdentity(t *testing.T) {
	base := "set security zones security-zone inside\nset security address-book first address host 192.0.2.1/32\nset security address-book second address host 192.0.2.2/32\n"
	a := parse(t, base+"set security address-book first attach zone inside\n")
	b := parse(t, base+"set security address-book second attach zone inside\n")
	if a.SemanticDigest() == b.SemanticDigest() {
		t.Fatal("address book attachment was lost from sealed graph")
	}
}
