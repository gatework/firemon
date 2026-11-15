package netconnector

import (
	"context"
	"regexp"
	"strings"
	"time"

	expect "github.com/gatework/go-expect"
	"github.com/gatework/net-connector/connector"
	"github.com/gatework/net-connector/vendors"
)

// Driver accepts a canonical vendor name, reuses the pinned connector's native
// drivers and adds ASA/ScreenOS.
// SRX accepts configuration prompts because the adapter owns its exclusive
// candidate session. It does not enable legacy SSH recovery.
func Driver(vendor string) (connector.Driver, error) {
	name := profileName(vendor)
	switch vendor {
	case "hillstone", "paloalto", "fortinet":
		return builtinDriver(name)
	case "srx":
		p, err := builtinDriver(name)
		if err != nil {
			return p, err
		}
		grammar := p.Terminal()
		grammar.CommandPrompt = textPattern(`(?:\A|[\r\n])[^\s@]+@[^\s>#]+[>#][ \t]*\z`)
		return connector.WithTerminal(p, grammar), nil
	case "huawei":
		p, err := builtinDriver(name)
		// USG persists with save and a native confirmation interaction. Do not
		// pass the Comware-specific force token as a Huawei filename.
		if err != nil {
			return nil, err
		}
		grammar := p.Terminal()
		grammar.SaveCommands = []string{"save"}
		return connector.WithTerminal(p, grammar), nil
	case "netscreen":
		prompt := textPattern(`(?:\A|[\r\n])[A-Za-z0-9_.:/-]+(?:\([^\r\n()]*\))?->[ \t]*\z`)
		return connector.StaticDriver{Grammar: connector.Terminal{
			Name: name, LoginPrompt: prompt, CommandPrompt: prompt,
			UsernamePrompt: textPattern(`(?i)(?:\A|[\r\n])[ \t]*login:[ \t]*\z`),
			PasswordPrompt: textPattern(`(?i)(?:\A|[\r\n])[ \t]*password:[ \t]*\z`),
			Pager:          textPattern(`(?i)(?:\A|[\r\n])[ \t]*--- more ---[^\r\n]*\z`), PagerResponse: " ",
			AuthenticationErrors: []*regexp.Regexp{regexp.MustCompile(`(?im)^[ \t]*(?:Login failed|Authentication failed|Access denied)\b`)},
			CommandErrors:        []*regexp.Regexp{regexp.MustCompile(`(?im)^[ \t]*(?:Unknown keyword|Invalid command|Invalid operation|Error:|Command failed|Access denied)\b`)},
			ConfigCommands:       []string{"get config"}, SaveCommands: []string{"save"},
			CommandTimeout: time.Minute, LegacyCryptoArguments: []string{},
		}}, nil
	case "asa":
		stem := `(?:\A|[\r\n])[A-Za-z0-9_.:/-]+(?:\([A-Za-z0-9_/-]+\))?`
		return connector.StaticDriver{Grammar: connector.Terminal{
			Name:                  name,
			LoginPrompt:           textPattern(stem + `[>#][ \t]*\z`),
			CommandPrompt:         textPattern(stem + `[>#][ \t]*\z`),
			UsernamePrompt:        textPattern(`(?i)(?:\A|[\r\n])[ \t]*Username:[ \t]*\z`),
			PasswordPrompt:        textPattern(`(?i)(?:\A|[\r\n])[ \t]*Password:[ \t]*\z`),
			PrivilegeCommand:      "enable",
			PrivilegePrompt:       textPattern(stem + `#[ \t]*\z`),
			Pager:                 textPattern(`(?m)(?:\A|[\r\n])[ \t]*<--- More --->[ \t]*\z`),
			PagerResponse:         " ",
			AuthenticationErrors:  []*regexp.Regexp{regexp.MustCompile(`(?im)^(?:%[ \t]*)?(?:Access denied|Authentication failed|Login invalid)\b`)},
			CommandErrors:         []*regexp.Regexp{regexp.MustCompile(`(?im)^[ \t]*(?:ERROR:|Error:|%[ \t]*(?:Invalid|Incomplete|Ambiguous|Error)\b)`)},
			ConfigCommands:        []string{"terminal pager 0", "show running-config"},
			SaveCommands:          []string{"write memory"},
			CommandTimeout:        time.Minute,
			LegacyCryptoArguments: []string{},
		}, Save: func(ctx context.Context, result connector.Result) error {
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
		return nil, ErrInvalid
	}
}

// profileName maps canonical vendors to the pinned connector's profile names.
func profileName(vendor string) string {
	switch vendor {
	case "paloalto":
		return "palo_alto"
	case "srx":
		return "juniper"
	case "huawei", "hillstone", "fortinet", "netscreen", "asa":
		return vendor
	}
	return ""
}

func confirmASA(step connector.StepResult) error {
	text, err := persistenceText(step)
	if err != nil {
		return err
	}
	building, ok := false, false
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimSpace(line)
		building = building || line == "Building configuration..."
		ok = ok || line == "[OK]"
	}
	if !building || !ok {
		return ErrPersistence
	}
	return nil
}

func builtinDriver(name string) (connector.Driver, error) {
	platform, err := vendors.NewBuiltinRegistry().Lookup(name)
	if err != nil {
		return nil, err
	}
	return platform, nil
}

// textPattern compiles package-owned, static prompt expressions.
func textPattern(expression string) expect.Pattern {
	pattern, err := expect.Compile(expression)
	if err != nil {
		panic(err)
	}
	return pattern
}
