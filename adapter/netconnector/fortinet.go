package netconnector

import (
	"context"
	"regexp"
	"strings"

	"github.com/gatework/go-net-connector/connector"
)

var vdomName = regexp.MustCompile(`\A[A-Za-z0-9_.-]{1,79}\z`)

// Read the native current domain before entering a domain. Checking inventory
// first prevents "edit" from silently creating a missing VDOM.
func (s *Session) fortinetContext(ctx context.Context, op *connector.Operation, b *responseBudget) error {
	if !vdomName.MatchString(s.metadata.Context) {
		return ErrInvalid
	}
	current, multiple, err := fortinetStatus(ctx, op, b)
	if err != nil {
		return err
	}
	if current == s.metadata.Context {
		return nil
	}
	if !multiple {
		return ErrCapture
	}
	if err := fortinetGlobal(ctx, op, b); err != nil {
		return err
	}
	step, err := b.command(ctx, op, "diagnose sys vd list")
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(configBody(step.Output(), step.Command().Text, step.Prompt()), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == "name="+s.metadata.Context && strings.HasPrefix(fields[1], "index=") {
			found = true
		}
	}
	if !found {
		return ErrCapture
	}
	for _, command := range []string{"end", "config vdom", `edit "` + s.metadata.Context + `"`} {
		if _, err := b.command(ctx, op, command); err != nil {
			return err
		}
	}
	current, _, err = fortinetStatus(ctx, op, b)
	if err != nil {
		return err
	}
	if current != s.metadata.Context {
		return ErrCapture
	}
	return nil
}

func fortinetStatus(ctx context.Context, op *connector.Operation, b *responseBudget) (string, bool, error) {
	step, err := b.command(ctx, op, "get system status")
	if err != nil {
		return "", false, err
	}
	current, mode := "", ""
	for _, line := range strings.Split(configBody(step.Output(), step.Command().Text, step.Prompt()), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Current virtual domain":
			current = strings.TrimSpace(value)
		case "Virtual domain configuration":
			mode = strings.TrimSpace(value)
		}
	}
	if !vdomName.MatchString(current) || mode != "enable" && mode != "disable" && mode != "multiple" && mode != "split-task" {
		return "", false, ErrCapture
	}
	return current, mode != "disable", nil
}

func fortinetGlobal(ctx context.Context, op *connector.Operation, b *responseBudget) error {
	if strings.Contains(op.CurrentPrompt(), "(global)") {
		return nil
	}
	if strings.Contains(op.CurrentPrompt(), "(") {
		if _, err := b.command(ctx, op, "end"); err != nil {
			return err
		}
	}
	_, err := b.command(ctx, op, "config global")
	return err
}

// FortiOS automatic mode persists each completed native edit to both memory and
// flash. Manual/revert/workspace running output is never labeled saved output.
// The surrounding read checks the mode twice and changes no device setting.
func (s *Session) fortinetAutomatic(ctx context.Context, op *connector.Operation, b *responseBudget) error {
	_, multiple, err := fortinetStatus(ctx, op, b)
	if err != nil {
		return err
	}
	if multiple {
		if err := fortinetGlobal(ctx, op, b); err != nil {
			return err
		}
	}
	step, err := b.command(ctx, op, "show full-configuration system global")
	if err != nil {
		return err
	}
	text, err := persistenceText(step)
	if err != nil {
		return err
	}
	mode, count := "", 0
	for _, line := range strings.Split(configBody(text, step.Command().Text, step.Prompt()), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "set" && fields[1] == "cfg-save" {
			if len(fields) != 3 {
				return ErrPersistence
			}
			mode, count = fields[2], count+1
		}
	}
	if mode != "automatic" || count != 1 {
		return ErrPersistence
	}
	if multiple {
		_, err = b.command(ctx, op, "end")
	}
	return err
}
