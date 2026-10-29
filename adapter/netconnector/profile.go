package netconnector

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/gatework/go-net-connector/connector"
	"github.com/gatework/go-net-connector/vendors"
)

// Profile reuses the pinned connector's native dialects and adds ASA/ScreenOS.
// SRX accepts configuration prompts because the adapter owns its exclusive
// candidate session. It does not enable legacy SSH recovery.
func Profile(vendor string) (connector.Profile, error) {
	switch domainVendor(vendor) {
	case "hillstone":
		return vendors.Profile("hillstone")
	case "paloalto":
		return vendors.Profile("palo_alto")
	case "srx":
		p, err := vendors.Profile("juniper")
		if err != nil {
			return p, err
		}
		p.CommandPrompt = regexp.MustCompile(`(?:\A|[\r\n])[^\s@]+@[^\s>#]+[>#][ \t]*\z`)
		return p, nil
	case "fortinet":
		return vendors.Profile(domainVendor(vendor))
	case "huawei":
		p, err := vendors.Profile("huawei")
		// USG persists with save and a native confirmation interaction. Do not
		// pass the Comware-specific force token as a Huawei filename.
		p.SaveCommands = []string{"save"}
		return p, err
	case "netscreen":
		prompt := regexp.MustCompile(`(?:\A|[\r\n])[A-Za-z0-9_.:/-]+(?:\([^\r\n()]*\))?->[ \t]*\z`)
		return connector.Profile{
			Name: "netscreen", LoginPrompt: prompt, CommandPrompt: prompt,
			UsernamePrompt: regexp.MustCompile(`(?i)(?:\A|[\r\n])[ \t]*login:[ \t]*\z`),
			PasswordPrompt: regexp.MustCompile(`(?i)(?:\A|[\r\n])[ \t]*password:[ \t]*\z`),
			Pager:          regexp.MustCompile(`(?i)(?:\A|[\r\n])[ \t]*--- more ---[^\r\n]*\z`), PagerResponse: " ",
			AuthenticationErrors: []*regexp.Regexp{regexp.MustCompile(`(?im)^[ \t]*(?:Login failed|Authentication failed|Access denied)\b`)},
			CommandErrors:        []*regexp.Regexp{regexp.MustCompile(`(?im)^[ \t]*(?:Unknown keyword|Invalid command|Invalid operation|Error:|Command failed|Access denied)\b`)},
			ConfigCommands:       []string{"get config"}, SaveCommands: []string{"save"},
			CommandTimeout: time.Minute, LegacySSHArguments: []string{}, Capabilities: connector.Capabilities{Save: true},
		}, nil
	case "asa":
		stem := `(?:\A|[\r\n])[A-Za-z0-9_.:/-]+(?:\([A-Za-z0-9_/-]+\))?`
		return connector.Profile{
			Name:                 "asa",
			LoginPrompt:          regexp.MustCompile(stem + `[>#][ \t]*\z`),
			CommandPrompt:        regexp.MustCompile(stem + `[>#][ \t]*\z`),
			UsernamePrompt:       regexp.MustCompile(`(?i)(?:\A|[\r\n])[ \t]*Username:[ \t]*\z`),
			PasswordPrompt:       regexp.MustCompile(`(?i)(?:\A|[\r\n])[ \t]*Password:[ \t]*\z`),
			PrivilegeCommand:     "enable",
			PrivilegePrompt:      regexp.MustCompile(stem + `#[ \t]*\z`),
			Pager:                regexp.MustCompile(`(?m)(?:\A|[\r\n])[ \t]*<--- More --->[ \t]*\z`),
			PagerResponse:        " ",
			AuthenticationErrors: []*regexp.Regexp{regexp.MustCompile(`(?im)^(?:%[ \t]*)?(?:Access denied|Authentication failed|Login invalid)\b`)},
			CommandErrors:        []*regexp.Regexp{regexp.MustCompile(`(?im)^[ \t]*(?:ERROR:|Error:|%[ \t]*(?:Invalid|Incomplete|Ambiguous|Error)\b)`)},
			ConfigCommands:       []string{"terminal pager 0", "show running-config"},
			SaveCommands:         []string{"write memory"},
			CommandTimeout:       time.Minute,
			LegacySSHArguments:   []string{},
			Capabilities:         connector.Capabilities{Save: true},
			ValidateSave: func(ctx context.Context, result connector.Result) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				steps := result.Steps()
				if len(steps) != 1 || steps[0].Command().Text != "write memory" {
					return ErrPersistence
				}
				return confirmASA(steps[0])
			},
		}, nil
	default:
		return connector.Profile{}, ErrInvalid
	}
}

func confirmASA(step connector.StepResult) error {
	text, err := persistenceText(step)
	if err != nil {
		return err
	}
	building, ok := false, false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		building = building || line == "Building configuration..."
		ok = ok || line == "[OK]"
	}
	if !building || !ok {
		return ErrPersistence
	}
	return nil
}
