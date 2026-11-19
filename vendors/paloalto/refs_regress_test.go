package paloalto_test

import (
	"testing"

	"github.com/gatework/firemon"
)

// Objects that only decryption rules or a PBF schedule use are in use:
// deleting them would break the device configuration.
func TestReferences_OtherRulebasesKeepObjectsLive(t *testing.T) {
	t.Parallel()
	_, fw := compileSet(t, `set address bank ip-netmask 192.0.2.50
set address branch ip-netmask 10.9.0.0/16
set schedule night schedule-type recurring daily [ 00:00-06:00 ]
set rulebase decryption rules no-decrypt destination bank
set rulebase decryption rules no-decrypt action no-decrypt
set rulebase pbf rules backup source branch
set rulebase pbf rules backup schedule night
`)
	refs := fw.References()
	for _, o := range []firemon.ObjectRef{
		{Kind: firemon.ObjectKindAddress, Name: "bank"},
		{Kind: firemon.ObjectKindAddress, Name: "branch"},
		{Kind: firemon.ObjectKindSchedule, Name: "night"},
	} {
		if !refs.Live(o) {
			t.Errorf("%s is used and must not be reported unused", o)
		}
	}
	if u := refs.Unused(); len(u) != 0 {
		t.Errorf("unused: %v", u)
	}
}
