package netscreen

import (
	"slices"

	"github.com/gatework/firemon/config"
)

// A policy continuation and a virtual-router body own their commands. Root-like
// text in either body or an unsupported virtual system cannot create objects.
func scopeRows(statements []config.Statement) []row {
	out := make([]row, 0, len(statements))
	scope, owner, vrf, defaultVR := "root", "", "trust-vr", "trust-vr"
	for _, s := range statements {
		w := s.Words
		if scope == "root" && begins(w, "set", "vsys") {
			scope = "unsupported"
		}
		if scope != "unsupported" && scope != "router" && begins(w, "set", "policy", "id") && len(w) >= 4 {
			scope, owner = "policy", w[3]
		}
		if scope == "root" && begins(w, "set", "vrouter") {
			if len(w) == 3 {
				scope, owner, vrf = "router", w[2], w[2]
			}
			if len(w) == 4 && w[2] == "name" {
				scope, owner, vrf = "router", w[3], w[3]
			}
			if len(w) == 4 && w[3] == "default-vrouter" {
				defaultVR = w[2]
			}
		}
		routeVR := defaultVR
		if scope == "router" {
			routeVR = vrf
		}
		out = append(out, row{Statement: s, scope: scope, owner: owner, vrf: routeVR})
		if scope == "router" && slices.Equal(w, []string{"set", "default-vrouter"}) {
			defaultVR = vrf
		}
		if slices.Equal(w, []string{"exit"}) && scope != "unsupported" {
			scope, owner = "root", ""
		}
	}
	return out
}
