package huawei_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/huawei"
)

func TestCancellationAndCumulativeBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := huawei.Parse(ctx, config.Source{Text: basic, Complete: true}, fm.Metadata{Device: "synthetic"}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	fw := parse(t, strings.Replace(basic, "return\n", nativeNAT, 1))
	q := policy.Request{FromZone: "untrust", ToZone: "trust", Traffic: traffic(t, "203.0.113.10/32", "198.51.100.60/32", 6, 1000, 8443)}
	if _, err := (policy.Engine{}).QueryPacket(ctx, fw, policy.PacketRequest{Request: q}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := (policy.Engine{Limits: policy.Limits{Rules: 2}}).QueryNAT(context.Background(), fw, q); !errors.Is(err, policy.ErrBudget) {
		t.Fatal(err)
	}
	if _, err := (policy.Engine{Limits: policy.Limits{Rules: 2}}).QueryPacket(context.Background(), fw, policy.PacketRequest{Request: q}); !errors.Is(err, policy.ErrBudget) {
		t.Fatal(err)
	}
	if _, err := (huawei.Renderer{}).Render(context.Background(), fw, fw, []plan.Change{{Kind: plan.CreateRule, Rule: "absent1"}, {Kind: plan.CreateRule, Rule: "absent2"}}); err == nil {
		t.Fatal("invalid renderer input accepted")
	}
}
func TestUnprovenReverseServerCannotBecomeUntranslatedTraffic(t *testing.T) {
	raw := strings.Replace(basic, "return\n", "nat server x protocol tcp global 198.51.100.2 443 inside 192.0.2.2 443\n", 1)
	fw := parse(t, raw)
	got, err := (policy.Engine{}).QueryNAT(context.Background(), fw, policy.Request{FromZone: "trust", ToZone: "untrust", Traffic: traffic(t, "192.0.2.2/32", "203.0.113.10/32", 6, 443, 8443)})
	if err != nil || got.Unknown.Empty() || !got.Unmatched.Empty() {
		t.Fatal("unknown reverse map fell through", got, err)
	}
}
func TestVPNRebindingClearsOldConnectedNetworks(t *testing.T) {
	raw := `ip route-static vpn-instance blue 203.0.113.0 24 198.51.100.254
#
interface GigabitEthernet1/0/1
 ip address 192.0.2.1 24
 ip binding vpn-instance blue
 ip address 198.51.100.1 24
#
firewall zone trust
 add interface GigabitEthernet1/0/1
#
`
	fw := parse(t, raw)
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	for _, r := range fw.Routes() {
		if r.Record().Scope != "blue" || r.Record().Destination.Addr().String() == "192.0.2.0" || r.Interface() != fw.Interface("GigabitEthernet1/0/1") {
			t.Fatal(r.Record())
		}
	}
}
func TestMalformedCaptureAndConflictingObjectTypesFail(t *testing.T) {
	for _, raw := range []string{"interface eth0\n ip address 192.0.2.1 24\n", "ip address-set x\n#\n", "ip address-set x type object\n#\nip address-set x type group\n#\n", "security-policy\n rule name\n#\n"} {
		if _, err := huawei.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{}); !errors.Is(err, config.ErrSource) {
			t.Fatal(raw, err)
		}
	}
}
func FuzzScopedCapture(f *testing.F) {
	f.Add(basic)
	f.Add(nativeNAT)
	f.Add("unknown\n interface fake\n  ip address 10.0.0.1 24\n#\n")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1<<16 {
			t.Skip()
		}
		fw, err := huawei.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "synthetic"})
		if err != nil {
			return
		}
		again, err := fm.Seal(fw.Export())
		if err != nil || again.SemanticDigest() != fw.SemanticDigest() {
			t.Fatal("unstable sealed graph", err)
		}
	})
}
