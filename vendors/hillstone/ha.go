package hillstone

import (
	"regexp"

	"github.com/gatework/firemon"
)

// haPrompt is the role StoneOS shows in its prompt on an HA member:
// "FW01(M)#" on the master, "FW02(B)#" on the backup.
var haPrompt = regexp.MustCompile(`\((M|B)\)[#>]\s*$`)

// HARole reads the runtime HA role from the device prompt. The output of
// a command is not needed: StoneOS marks the prompt of every HA member.
func HARole(prompt, _ string) firemon.HARole {
	switch m := haPrompt.FindStringSubmatch(prompt); {
	case m == nil:
		return firemon.HARoleUnknown
	case m[1] == "M":
		return firemon.HARoleActive
	default:
		return firemon.HARoleStandby
	}
}
