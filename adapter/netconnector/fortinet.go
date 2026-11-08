package netconnector

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/gatework/firemon/config"
	"github.com/gatework/go-net-connector/connector"
)

var vdomName = regexp.MustCompile(`\A[A-Za-z0-9_.-]{1,79}\z`)

// Read the native current domain before entering a domain. Checking inventory
// first prevents "edit" from silently creating a missing VDOM.
func (s *Session) fortinetContext(ctx context.Context, op *connector.Operation, b *responseBudget) error {
	if !vdomName.MatchString(s.meta.Context) {
		return ErrInvalid
	}
	current, multiple, err := fortinetStatus(ctx, op, b)
	if err != nil {
		return err
	}
	if current == s.meta.Context {
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
	body, err := responseBody(step)
	if err != nil {
		return err
	}
	found := false
	for line := range strings.SplitSeq(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == "name="+s.meta.Context && strings.HasPrefix(fields[1], "index=") {
			found = true
		}
	}
	if !found {
		return ErrCapture
	}
	for _, command := range []string{"end", "config vdom", `edit "` + s.meta.Context + `"`} {
		if _, err := b.command(ctx, op, command); err != nil {
			return err
		}
	}
	current, _, err = fortinetStatus(ctx, op, b)
	if err != nil {
		return err
	}
	if current != s.meta.Context {
		return ErrCapture
	}
	return nil
}

func fortinetStatus(ctx context.Context, op *connector.Operation, b *responseBudget) (string, bool, error) {
	step, err := b.command(ctx, op, "get system status")
	if err != nil {
		return "", false, err
	}
	body, err := responseBody(step)
	if err != nil {
		return "", false, err
	}
	current, mode := "", ""
	for line := range strings.SplitSeq(body, "\n") {
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
	prompt, err := op.Prompt()
	if err != nil {
		return err
	}
	if strings.Contains(prompt, "(global)") {
		return nil
	}
	if strings.Contains(prompt, "(") {
		if _, err := b.command(ctx, op, "end"); err != nil {
			return err
		}
	}
	_, err = b.command(ctx, op, "config global")
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
	text, err := responseHistory(step)
	if err != nil {
		return err
	}
	if err := confirmAutomatic(ctx, text, int(s.opts.MaxOutputBytes)); err != nil {
		return err
	}
	if multiple {
		_, err = b.command(ctx, op, "end")
	}
	return err
}

// confirmAutomatic proves one complete system global block. Other setting values
// are opaque data; a rejection outside a quoted value cannot become a statement.
func confirmAutomatic(ctx context.Context, text string, limit int) error {
	content, err := config.NewContent(ctx, config.Source{Text: text, Complete: true}, config.Limits{MaxBytes: limit})
	if err != nil {
		return errors.Join(ErrPersistence, err)
	}
	statements, err := config.Statements(ctx, content)
	if err != nil {
		return errors.Join(ErrPersistence, err)
	}
	opened, closed, automatic := false, false, false
	for _, statement := range statements {
		if err := ctx.Err(); err != nil {
			return err
		}
		words := statement.Words
		if len(words) == 0 {
			continue
		}
		switch {
		case closed:
			return ErrPersistence
		case !opened:
			if !slices.Equal(words, []string{"config", "system", "global"}) {
				return ErrPersistence
			}
			opened = true
		case len(words) == 1 && words[0] == "end":
			closed = true
		case len(words) >= 3 && words[0] == "set":
			if words[1] == "cfg-save" {
				if automatic || len(words) != 3 || words[2] != "automatic" {
					return ErrPersistence
				}
				automatic = true
			}
		default:
			return ErrPersistence
		}
	}
	if !closed || !automatic {
		return ErrPersistence
	}
	return ctx.Err()
}
