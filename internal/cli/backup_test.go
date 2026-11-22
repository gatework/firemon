package cli

import (
	"maps"
	"testing"

	"github.com/gatework/firemon/adapter/yamlfile"
)

func TestPairByName(t *testing.T) {
	t.Parallel()
	m := func(name, host string, ha bool) backupMember {
		return backupMember{name: name + "-" + host, host: host, ha: ha}
	}
	members := []backupMember{
		m("SHA2-IN-FW01", "192.0.2.1", true), m("SHA2-IN-FW02", "192.0.2.2", true),
		m("SZX8-FW01", "192.0.2.3", true), m("SZX8-FW02", "192.0.2.4", true),
		m("HUZ4-FW1", "192.0.2.5", true), m("HUZ4-FW2", "192.0.2.6", false), // only one runs HA
		m("SHA2-ISP-FW01", "192.0.2.7", true), // alone
		m("SZX9-IN-FW01", "192.0.2.8", true), m("SZX9-IN-FW02", "192.0.2.9", true),
	}
	topology := map[string]yamlfile.Firewall{
		"SZX9-IN-FW01-192.0.2.8": {Cluster: "SZX9-IN"}, "SZX9-IN-FW02-192.0.2.9": {Cluster: "SZX9-IN"},
	}
	want := map[string]string{
		"SHA2-IN-FW01-192.0.2.1": "SHA2-IN", "SHA2-IN-FW02-192.0.2.2": "SHA2-IN",
		"SZX8-FW01-192.0.2.3": "SZX8", "SZX8-FW02-192.0.2.4": "SZX8",
		"SZX9-IN-FW01-192.0.2.8": "SZX9-IN", "SZX9-IN-FW02-192.0.2.9": "SZX9-IN",
	}
	if got := pairByName(members, topology); !maps.Equal(got, want) {
		t.Errorf("clusters\n got %v\nwant %v", got, want)
	}
}
