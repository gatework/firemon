package netconnector

import (
	"context"
	"crypto/sha256"
	"regexp"
	"strings"

	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/go-net-connector/connector"
)

var _ deploy.ConfigurationSession = (*Session)(nil)
var configurationToken = regexp.MustCompile(`\A[0-9a-f]{48}\z`)

// BeginConfiguration acquires native candidate isolation before the caller's
// baseline capture. No candidate reset, takeover, retry or reconnect is used.
func (s *Session) BeginConfiguration(ctx context.Context, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !configurationToken.MatchString(token) {
		return ErrInvalid
	}
	return s.run(ctx, func(ctx context.Context, op *connector.Operation) error {
		if s.configurationToken != "" {
			return ErrConfigurationLock
		}
		b := responseBudget{remaining: s.options.MaxOutputBytes, digest: sha256.New()}
		switch s.metadata.Vendor {
		case "paloalto":
			if !s.options.ExclusivePANAdmin {
				return ErrConfigurationLock
			}
			locks, err := s.panLocks(ctx, op, &b)
			if err != nil {
				return err
			}
			if len(locks) != 0 {
				return ErrConfigurationLock
			}
			if _, err := b.command(ctx, op, `request config-lock add comment "firemon:`+token+`"`); err != nil {
				return err
			}
			locks, err = s.panLocks(ctx, op, &b)
			if err != nil {
				return err
			}
			if !ownPANLock(locks, op.CurrentPrompt(), token) {
				return ErrConfigurationLock
			}
			if err := cleanCandidate(ctx, op, &b, "show config diff"); err != nil {
				return err
			}
		case "fortinet":
			// Reject unsupported persistence before the baseline or any policy
			// write. Context selection only enters an existing verified VDOM.
			if err := s.fortinetAutomatic(ctx, op, &b); err != nil {
				return err
			}
			if err := s.fortinetContext(ctx, op, &b); err != nil {
				return err
			}
		case "srx":
			step, err := b.command(ctx, op, "configure exclusive")
			if err != nil {
				return err
			}
			text, err := persistenceText(step)
			if err != nil || !strings.Contains(text, "Entering configuration mode") || !strings.HasSuffix(strings.TrimSpace(step.Prompt()), "#") {
				return ErrConfigurationLock
			}
			s.srxExclusive = true
			if err := cleanCandidate(ctx, op, &b, "show | compare | no-more"); err != nil {
				return err
			}
		}
		s.configurationToken = token
		return nil
	})
}

// EndConfiguration verifies token ownership before release. Fresh recovery
// sessions can release PAN locks left by cancellation or process death. A dirty
// candidate is deliberately retained for explicit operator reconciliation.
func (s *Session) EndConfiguration(ctx context.Context, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !configurationToken.MatchString(token) {
		return ErrInvalid
	}
	return s.run(ctx, func(ctx context.Context, op *connector.Operation) error {
		if s.configurationToken != "" && s.configurationToken != token {
			return ErrConfigurationLock
		}
		b := responseBudget{remaining: s.options.MaxOutputBytes, digest: sha256.New()}
		switch s.metadata.Vendor {
		case "paloalto":
			if !s.options.ExclusivePANAdmin {
				return ErrConfigurationLock
			}
			locks, err := s.panLocks(ctx, op, &b)
			if err != nil {
				return err
			}
			if len(locks) != 0 && !ownPANLock(locks, op.CurrentPrompt(), token) {
				return ErrConfigurationLock
			}
			if err := cleanCandidate(ctx, op, &b, "show config diff"); err != nil {
				return err
			}
			// PAN automatically removes the lock when commit completes. An
			// absent lock is therefore valid; never remove an unrelated lock.
			if len(locks) != 0 {
				if _, err := b.command(ctx, op, "request config-lock remove"); err != nil {
					return err
				}
				locks, err = s.panLocks(ctx, op, &b)
				if err != nil {
					return err
				}
				if len(locks) != 0 {
					return ErrConfigurationLock
				}
			}
		case "srx":
			if s.srxExclusive {
				if err := cleanCandidate(ctx, op, &b, "show | compare | no-more"); err != nil {
					return err
				}
				if _, err := b.command(ctx, op, "exit"); err != nil {
					return err
				}
				s.srxExclusive = false
			}
		}
		s.configurationToken = ""
		return nil
	})
}

func cleanCandidate(ctx context.Context, op *connector.Operation, b *responseBudget, command string) error {
	step, err := b.command(ctx, op, command)
	if err != nil {
		return err
	}
	text, err := persistenceText(step)
	if err != nil {
		return err
	}
	body := configBody(text, command, step.Prompt())
	body = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(body), "[edit]"))
	if body != "" {
		return ErrCandidate
	}
	return nil
}

type panLock struct{ admin, comment string }

func (s *Session) verifyPANLock(ctx context.Context, op *connector.Operation, b *responseBudget) error {
	if s.configurationToken == "" {
		return ErrConfigurationLock
	}
	locks, err := s.panLocks(ctx, op, b)
	if err != nil {
		return err
	}
	if !ownPANLock(locks, op.CurrentPrompt(), s.configurationToken) {
		return ErrConfigurationLock
	}
	return nil
}

// Use the native XML display for lock identity rather than terminal column
// positions. The response path and owner attribute match Palo Alto's pango
// ConfigLocks and xmlapi.Lock (result/config-locks/entry, name attribute):
// https://github.com/PaloAltoNetworks/pango/blob/v0.10.2/client.go
// https://github.com/PaloAltoNetworks/pango/blob/main/xmlapi/lock.go
// Unrecognized nested forms fail closed instead of guessing ownership.
func (s *Session) panLocks(ctx context.Context, op *connector.Operation, b *responseBudget) ([]panLock, error) {
	if _, err := b.command(ctx, op, "set cli op-command-xml-output on"); err != nil {
		return nil, err
	}
	step, err := b.command(ctx, op, "show config-locks vsys all")
	if err != nil {
		return nil, err
	}
	text := configBody(step.Output(), step.Command().Text, step.Prompt())
	locks, parseErr := parsePANLocks(ctx, text, int(s.options.MaxOutputBytes))
	if parseErr != nil {
		return nil, parseErr
	}
	if _, err := b.command(ctx, op, "set cli op-command-xml-output off"); err != nil {
		return nil, err
	}
	return locks, nil
}

func parsePANLocks(ctx context.Context, text string, limit int) ([]panLock, error) {
	doc, err := config.XML(ctx, config.Source{Text: text, Complete: true}, config.Limits{MaxBytes: limit})
	if err != nil {
		return nil, ErrConfigurationLock
	}
	root := doc.Root
	if root.Name.Local == "response" {
		status := ""
		for _, a := range root.Attributes {
			if a.Name.Local == "status" {
				status = a.Value
			}
		}
		if status != "success" || len(root.Children) != 1 || root.Children[0].Name.Local != "result" {
			return nil, ErrConfigurationLock
		}
		root = root.Children[0]
	}
	if root.Name.Local == "result" {
		if len(root.Children) != 1 {
			return nil, ErrConfigurationLock
		}
		root = root.Children[0]
	}
	if root.Name.Local != "config-locks" || strings.TrimSpace(root.Text) != "" {
		return nil, ErrConfigurationLock
	}
	locks := make([]panLock, 0, len(root.Children))
	for _, entry := range root.Children {
		if entry.Name.Local != "entry" {
			return nil, ErrConfigurationLock
		}
		var lock panLock
		for _, a := range entry.Attributes {
			if a.Name.Local == "name" {
				lock.admin = a.Value
			}
		}
		comments := 0
		for _, field := range entry.Children {
			if len(field.Children) != 0 {
				return nil, ErrConfigurationLock
			}
			switch field.Name.Local {
			case "comment":
				comments++
				lock.comment = strings.TrimSpace(field.Text)
			}
		}
		if lock.admin == "" || comments != 1 {
			return nil, ErrConfigurationLock
		}
		locks = append(locks, lock)
	}
	return locks, nil
}

func ownPANLock(locks []panLock, prompt, token string) bool {
	admin, _, found := strings.Cut(strings.TrimSpace(prompt), "@")
	return found && len(locks) == 1 && locks[0].admin == admin && locks[0].comment == "firemon:"+token
}
