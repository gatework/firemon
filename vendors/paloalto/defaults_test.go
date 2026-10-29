package paloalto_test

import (
	"context"
	"net/netip"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/paloalto"
)

const zones = "set network interface ethernet eth1 layer3 ip 192.0.2.1/24\nset network interface ethernet eth2 layer3 ip 198.51.100.1/24\nset zone inside network layer3 eth1\nset zone outside network layer3 eth2\n"

func pan(t *testing.T, raw string) *fm.Firewall {
	t.Helper()
	fw, err := paloalto.Parse(context.Background(), config.Source{Text: raw, Complete: true}, fm.Metadata{Device: "pan"})
	if err != nil {
		t.Fatal(err)
	}
	return fw
}
func packet(t *testing.T) flow.Traffic {
	t.Helper()
	src, _ := flow.PrefixRange(netip.MustParsePrefix("192.0.2.9/32"))
	dst, _ := flow.PrefixRange(netip.MustParsePrefix("198.51.100.9/32"))
	tt, err := flow.NewTraffic(8, flow.Box{Source: src, Destination: dst, Protocol: flow.Interval{Low: 6, High: 6}, SourcePort: flow.Interval{Low: 1024, High: 65535}, DestinationPort: flow.Interval{Low: 443, High: 443}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
	if err != nil {
		t.Fatal(err)
	}
	return tt
}
func TestPANImplicitDefaultRulesUseZoneRelationshipAndUnknownZoneEvidence(t *testing.T) {
	fw := pan(t, zones)
	for _, tt := range []struct {
		from, to fm.ID
		want     fm.Action
	}{{"inside", "inside", fm.Permit}, {"inside", "outside", fm.Deny}, {"", "outside", fm.UnknownAction}, {"missing", "missing", fm.UnknownAction}} {
		r, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: packet(t), FromZone: tt.from, ToZone: tt.to})
		if err != nil {
			t.Fatal(err)
		}
		switch tt.want {
		case fm.Permit:
			if !r.Complete || r.Allowed.Empty() {
				t.Fatal("intrazone did not permit", r)
			}
		case fm.Deny:
			if !r.Complete || r.Denied.Empty() {
				t.Fatal("interzone did not deny", r)
			}
		default:
			if r.Complete || r.Unknown.Empty() {
				t.Fatal("missing zone became certain", r)
			}
		}
	}
}
func TestPANDefaultOverrideAndExplicitIntrazoneRuleRespectNativeOrder(t *testing.T) {
	raw := zones + "set rulebase default-security-rules rules intrazone-default action deny\nset rulebase security rules local from any\nset rulebase security rules local to any\nset rulebase security rules local source any\nset rulebase security rules local destination any\nset rulebase security rules local service any\nset rulebase security rules local application any\nset rulebase security rules local rule-type intrazone\nset rulebase security rules local action allow\n"
	fw := pan(t, raw)
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	for _, zone := range []fm.ID{"inside", "outside"} {
		r, err := (policy.Engine{}).Query(context.Background(), fw, policy.Request{Traffic: packet(t), FromZone: "inside", ToZone: zone})
		if err != nil {
			t.Fatal(err)
		}
		if zone == "inside" && r.Allowed.Empty() || zone == "outside" && r.Denied.Empty() {
			t.Fatal("intrazone rule ignored native relationship/order", r)
		}
	}
	if len(fw.Rules()) != 3 {
		t.Fatal("overrides duplicated implicit rules")
	}
}
func TestPANLogStartAndLogEndRemainDistinctForReadback(t *testing.T) {
	rule := "set rulebase security rules web from any\nset rulebase security rules web to any\nset rulebase security rules web source any\nset rulebase security rules web destination any\nset rulebase security rules web service any\nset rulebase security rules web action allow\n"
	a := pan(t, zones+rule+"set rulebase security rules web log-start yes\nset rulebase security rules web log-end no\n")
	b := pan(t, zones+rule+"set rulebase security rules web log-start no\nset rulebase security rules web log-end yes\n")
	if a.SemanticDigest() == b.SemanticDigest() {
		t.Fatal("distinct native log events collapsed")
	}
}
