package hillstone_test

import (
	"testing"

	fm "github.com/gatework/firemon"
)

func TestQoSReferencesStayOutsideSecurityDeclarations(t *testing.T) {
	for _, nested := range []string{
		"qos-engine engine\n  root-pipe root id 1\n    schedule work\n    pipe child id 2\n      schedule work\n    exit\n  exit\nexit\n",
		"qos-engine engine\nroot-pipe root id 1\nschedule work\nexit\nexit\n",
		"future-feature example\n  schedule work\n  rule id 99\n    action permit\n  exit\nexit\n",
	} {
		t.Run(nested[:10], func(t *testing.T) {
			fw := parse(t, "schedule work\nperiodic daily 09:00 to 17:00\nexit\n"+nested+"rule id 1\nsrc-addr any\ndst-addr any\nservice any\naction deny\nexit\n")
			if len(fw.Schedules()) != 1 || fw.RuleCount() != 1 || fw.Rule("1") == nil {
				t.Fatal("nested references became declarations")
			}
			if fw.Complete() {
				t.Fatal("unknown configuration lost evidence")
			}
		})
	}
}

func TestNestedUnknownRuleConditionRemainsUnknown(t *testing.T) {
	fw := parse(t, "rule id 1\n  src-addr any\n  dst-addr any\n  service any\n  future-condition choice\n    action permit\n  exit\n  action permit\nexit\n")
	r := fw.Rule("1").Record()
	if len(r.Unsupported) == 0 || len(r.Match.Unsupported) == 0 {
		t.Fatal("nested condition became an unrestricted rule")
	}
	if fw.Export().Evidence[5].State != fm.Pending {
		t.Fatal("unknown child was consumed")
	}
}

func TestEmptyNestedBlocksDoNotCloseParent(t *testing.T) {
	fw := parse(t, "ips profile inspection\n  web-server\n    # empty child\n  \n  exit\nexit\n"+
		"aaa-server local\n  password-control\n  exit\nexit\n"+
		"interface-group ports\ninterface ge0\nexit\n"+
		"zone inside\nexit\n")
	if len(fw.Interfaces()) != 0 || fw.Zone("inside") == nil {
		t.Fatal("outside scope leaked into firewall declarations")
	}
	for _, d := range fw.Diagnostics() {
		if d.Code == "unexpected-exit" || d.Code == "unclosed-block" {
			t.Fatal(d.Code)
		}
	}
}

func TestTunnelBindingsRemainMembersDespiteExportIndentation(t *testing.T) {
	fw := parse(t, "tunnel scvpn remote-access\n  interface ge0\n    domain-route example.test\nexit\n"+
		"ip vrouter blue\nsnatrule id 1 from any to any service any trans-to 203.0.113.1 mode dynamicport\nexit\n")
	if len(fw.Interfaces()) != 0 || fw.DynamicNAT("blue/snat:1") == nil {
		t.Fatal("tunnel member swallowed subsequent routing context")
	}
}
