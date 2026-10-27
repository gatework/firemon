package netconnector

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/go-net-connector/connector"
)

// Read captures running or persistent configuration independently. Complete
// describes transport completeness; the vendor parser still decides semantics.
func (s *Session) Read(ctx context.Context, view deploy.View) (capture deploy.Capture, err error) {
	if view != deploy.Running && view != deploy.Saved {
		return capture, ErrInvalid
	}
	capture.Metadata = s.metadata
	capture.Metadata.SourceDigest, capture.Metadata.ParserVersion = "", ""
	err = s.run(ctx, func(ctx context.Context, op *connector.Operation) error {
		if view == deploy.Running {
			result, err := op.RunningConfig(ctx)
			text, complete := result.Config()
			steps := result.Steps()
			if len(steps) > 0 {
				last := steps[len(steps)-1]
				if !complete {
					text = last.Output()
				}
				text = configBody(text, last.Command().Text, last.Prompt())
			}
			capture.Source.Text = text
			if err != nil || !complete {
				return errors.Join(ErrCapture, err)
			}
		} else {
			pager, command := "", ""
			switch s.metadata.Vendor {
			case "asa":
				pager, command = "terminal pager 0", "show startup-config"
			case "hillstone":
				pager, command = "terminal length 0", "show configuration startup"
			case "paloalto":
				pager, command = "set cli pager off", "show config saved running-config.xml"
			default:
				return ErrInvalid
			}
			budget := responseBudget{remaining: s.options.MaxOutputBytes, digest: sha256.New()}
			if _, err := budget.command(ctx, op, pager); err != nil {
				return err
			}
			step, err := budget.command(ctx, op, command)
			if err != nil {
				return err
			}
			capture.Source.Text = configBody(step.Output(), command, step.Prompt())
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
