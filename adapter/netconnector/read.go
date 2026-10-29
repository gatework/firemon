package netconnector

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/device"
	"github.com/gatework/go-net-connector/connector"
)

// Read captures running or persistent configuration independently. Complete
// describes transport completeness; the vendor parser still decides semantics.
func (s *Session) Read(ctx context.Context, view device.View) (capture device.Capture, err error) {
	if view != device.Running && view != device.Saved {
		return capture, ErrInvalid
	}
	capture.Metadata = s.metadata
	capture.Metadata.SourceDigest, capture.Metadata.ParserVersion = "", ""
	err = s.run(ctx, func(ctx context.Context, op *connector.Operation) error {
		budget := responseBudget{remaining: s.options.MaxOutputBytes, digest: sha256.New()}
		switch {
		case s.metadata.Vendor == "srx":
			// Operational show configuration is the last committed database,
			// while configuration-mode show is the shared candidate.
			command := "show configuration | display set | no-more"
			if s.srxExclusive {
				command = "run " + command
			}
			text, err := budget.capture(ctx, op, command)
			capture.Source.Text = text
			if err != nil {
				return err
			}
			capture.Source.Text = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(text), "[edit]"))
		case s.metadata.Vendor == "fortinet":
			if view == device.Saved {
				if err := s.fortinetAutomatic(ctx, op, &budget); err != nil {
					return err
				}
			}
			if err := s.fortinetContext(ctx, op, &budget); err != nil {
				return err
			}
			text, err := budget.capture(ctx, op, "show full-configuration")
			capture.Source.Text = text
			if err != nil {
				return err
			}
			if view == device.Saved {
				if err := s.fortinetAutomatic(ctx, op, &budget); err != nil {
					return err
				}
			}
		case view == device.Running:
			result, err := op.RunningConfig(ctx)
			_, complete := result.Config()
			text, evidenceErr := captureEvidence(result, s.runningCommand(), s.options.MaxOutputBytes)
			capture.Source.Text = text
			if err != nil || evidenceErr != nil || !complete {
				return errors.Join(ErrCapture, err, evidenceErr)
			}
		default:
			pager, command := "", ""
			switch s.metadata.Vendor {
			case "asa":
				pager, command = "terminal pager 0", "show startup-config"
			case "hillstone":
				pager, command = "terminal length 0", "show configuration startup"
			case "paloalto":
				pager, command = "set cli pager off", "show config saved running-config.xml"
			case "netscreen":
				command = "get config saved"
			case "huawei":
				pager, command = "screen-length 0 temporary", "display saved-configuration"
			default:
				return ErrInvalid
			}
			if pager != "" {
				if _, err := budget.command(ctx, op, pager); err != nil {
					return err
				}
			}
			text, err := budget.capture(ctx, op, command)
			capture.Source.Text = text
			if err != nil {
				return err
			}
			if s.metadata.Vendor == "paloalto" {
				xml, err := config.XML(ctx, config.Source{Text: capture.Source.Text, Complete: true}, config.Limits{MaxBytes: int(s.options.MaxOutputBytes)})
				if err != nil || xml.Root == nil || xml.Root.Name.Local != "config" {
					return errors.Join(ErrCapture, err)
				}
			}
		}
		if strings.TrimSpace(capture.Source.Text) == "" || !utf8.ValidString(capture.Source.Text) {
			return ErrCapture
		}
		if int64(len(capture.Source.Text)) > s.options.MaxOutputBytes {
			return ErrLimit
		}
		capture.Source.Complete = true
		return nil
	})
	capture.Metadata.CapturedAt = time.Now().UTC()
	if err != nil {
		capture.Source.Complete = false
	}
	return
}

// capture keeps received evidence even when the command fails. Persistence and
// preflight commands continue to use command, which requires an accepted step.
func (b *responseBudget) capture(ctx context.Context, op *connector.Operation, command string) (string, error) {
	limit := b.remaining
	if limit <= 0 {
		return "", ErrLimit
	}
	result, err := op.ExecuteCommand(ctx, connector.Command{Text: command, Sensitive: true, OutputSensitive: true}, connector.ExecuteOptions{MaxOutputBytes: limit})
	text, evidenceErr := captureEvidence(result, command, limit)
	return text, errors.Join(err, b.record(result), evidenceErr)
}

// runningCommand identifies the configuration payload in the validated profile,
// excluding setup commands and PAN's checks after its configuration-mode show.
func (s *Session) runningCommand() string {
	commands := s.device.ConfigCommands()
	if s.metadata.Vendor == "paloalto" {
		for _, command := range commands {
			if command == "show" {
				return command
			}
		}
	}
	if len(commands) == 0 {
		return ""
	}
	return commands[len(commands)-1]
}

// captureEvidence binds output to the requested configuration command. The
// pinned connector exposes only Raw for failed attempts; these bytes are kept
// as incomplete evidence, without guessing encoding or terminal rendering.
func captureEvidence(result connector.Result, command string, limit int64) (string, error) {
	text, prompt := "", ""
	found := false
	steps := result.Steps()
	for i := len(steps) - 1; i >= 0; i-- {
		if steps[i].Command().Text == command {
			text, prompt, found = steps[i].Output(), steps[i].Prompt(), true
			if configuration, complete := result.Config(); complete {
				text = configuration
			}
			break
		}
	}
	if !found {
		attempts := result.Attempts()
		for i := len(attempts) - 1; i >= 0; i-- {
			if attempts[i].Command().Text == command {
				text, prompt = attempts[i].Raw(), attempts[i].Prompt()
				break
			}
		}
	}
	var err error
	if int64(len(text)) > limit {
		text, err = text[:max(0, limit)], ErrLimit
	}
	return configBody(text, command, prompt), err
}

// configBody removes only the command echo and terminal prompt. In particular,
// unknown native statements and configuration headers are retained for parsing.
func configBody(text, command, prompt string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimSpace(text)
	prompt = strings.TrimSpace(prompt)
	if !strings.Contains(text, "\n") {
		if text == prompt || text == command {
			return ""
		}
	} else {
		pos := strings.LastIndexByte(text, '\n')
		if strings.TrimSpace(text[pos+1:]) == prompt {
			text = text[:pos]
		}
	}
	first, rest, found := strings.Cut(text, "\n")
	if strings.TrimSpace(first) == command || strings.TrimSpace(first) == prompt+command {
		if !found {
			return ""
		}
		text = rest
	}
	return strings.Trim(text, "\r\n")
}
