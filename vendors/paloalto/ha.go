package paloalto

import (
	"regexp"
	"strings"

	"github.com/gatework/firemon"
)

// HAStateCommand shows the local HA state, for devices whose prompt does
// not carry it.
const HAStateCommand = "show high-availability state"

var (
	// haPrompt is the role PAN-OS shows in its prompt on an HA member:
	// "admin@PA(active)>" or "admin@PA(passive)#".
	haPrompt = regexp.MustCompile(`\((active|passive|active-primary|active-secondary)\)[#>]\s*$`)
	// haLocalState is "State: active (last ...)" in the Local Information
	// section of "show high-availability state".
	haLocalState = regexp.MustCompile(`(?m)^\s*State:\s*([a-z-]+)`)
)

// HARole reads the runtime HA role from the prompt, or else from the
// output of HAStateCommand. Active-active members are both active.
func HARole(prompt, output string) firemon.HARole {
	if m := haPrompt.FindStringSubmatch(prompt); m != nil {
		return haRole(m[1])
	}
	_, local, ok := strings.Cut(output, "Local Information:")
	if !ok {
		return firemon.HARoleUnknown
	}
	if peer := strings.Index(local, "Peer Information:"); peer >= 0 {
		local = local[:peer]
	}
	if m := haLocalState.FindStringSubmatch(local); m != nil {
		return haRole(m[1])
	}
	return firemon.HARoleUnknown
}

func haRole(state string) firemon.HARole {
	switch state {
	case "active", "active-primary", "active-secondary":
		return firemon.HARoleActive
	case "passive":
		return firemon.HARoleStandby
	default: // initial, non-functional, suspended, tentative
		return firemon.HARoleUnknown
	}
}
