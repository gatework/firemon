package hillstone_test

import (
	"testing"

	fm "github.com/gatework/firemon"
)

func TestUnsupportedBlockHeadersRemainPending(t *testing.T) {
	const members = "src-addr any\ndst-addr any\nservice any\naction permit\nexit\n"
	for _, tc := range []struct {
		name, source string
		line         int
	}{
		{"address suffix", "address a unsupported\nip 192.0.2.1/32\nexit\n", 1},
		{"global policy suffix", "policy-global unsupported\nrule id 1\n" + members + "exit\n", 1},
		{"rule suffix", "policy-global\nrule id 1 unsupported\n" + members + "exit\n", 2},
		{"policy zone suffix", "policy from inside to outside unsupported\nexit\n", 1},
		{"router suffix", "ip vrouter blue unsupported\nexit\n", 1},
		{"schedule suffix", "schedule daily unsupported\nexit\n", 1},
		{"nested invalid policy", "policy-global unsupported\nrule id 1\n" + members + "rule id 2\n" + members + "exit\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fw := parse(t, tc.source)
			if fw.Complete() {
				t.Fatal("unsupported header was accepted as complete")
			}
			if fw.Export().Evidence[tc.line-1].State != fm.Pending {
				t.Fatal("unsupported header was claimed")
			}
			if len(fw.Rules()) != 0 || len(fw.Addresses()) != 0 || len(fw.Schedules()) != 0 {
				t.Fatal("unknown block produced an understood firewall object")
			}
		})
	}
}
