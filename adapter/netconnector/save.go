package netconnector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/firemon/deploy"
	"github.com/gatework/go-net-connector/connector"
)

func responseDigest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

type responseBudget struct {
	remaining int64
	digest    hash.Hash
}

func (b *responseBudget) record(result connector.Result) error {
	for _, attempt := range result.Attempts() {
		raw := attempt.Raw()
		b.remaining -= int64(len(raw))
		fmt.Fprintf(b.digest, "%d:", len(raw))
		_, _ = b.digest.Write([]byte(raw))
	}
	if b.remaining < 0 {
		return ErrLimit
	}
	return nil
}
func (b *responseBudget) command(ctx context.Context, op *connector.Operation, text string) (connector.StepResult, error) {
	if b.remaining <= 0 {
		return connector.StepResult{}, ErrLimit
	}
	result, err := op.ExecuteCommand(ctx, connector.Command{Text: text, Sensitive: true, OutputSensitive: true}, connector.ExecuteOptions{MaxOutputBytes: b.remaining})
	if limitErr := b.record(result); err == nil {
		err = limitErr
	}
	if err != nil {
		return connector.StepResult{}, err
	}
	steps := result.Steps()
	if len(steps) != 1 || steps[0].Command().Text != text {
		return connector.StepResult{}, ErrPersistence
	}
	return steps[0], nil
}

var color = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var failure = regexp.MustCompile(`(?i)\b(?:error|failed|failure|denied|cannot|unable|unsuccessful|aborted)\b`)
var panEnqueued = regexp.MustCompile(`(?m)^[ \t]*Commit job enqueued with jobid[ \t]+([1-9][0-9]{0,9})[ \t]*$`)
var panProgress = regexp.MustCompile(`(?m)^[ \t]*Commit job[ \t]+([1-9][0-9]{0,9}) is in progress\.?[ \t]*$`)

// persistenceText checks the response history so a later carriage return or
// terminal rendering cannot erase an earlier device rejection.
func persistenceText(step connector.StepResult) (string, error) {
	text := color.ReplaceAllString(step.Raw(), "")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	for _, r := range text {
		if r < 32 && r != '\n' && r != '\t' || r == 127 {
			return "", ErrPersistence
		}
	}
	if failure.MatchString(text) {
		return "", ErrPersistence
	}
	return text, nil
}

// Save produces one durable receipt only after affirmative vendor persistence
// evidence. A lost response retires the session and never repeats save/commit.
func (s *Session) Save(ctx context.Context, receive deploy.ReceiptFunc) (out deploy.Outcome, err error) {
	if receive == nil {
		return out, ErrInvalid
	}
	err = s.run(ctx, func(ctx context.Context, op *connector.Operation) error {
		b := responseBudget{remaining: s.options.MaxOutputBytes, digest: sha256.New()}
		switch s.metadata.Vendor {
		case "hillstone":
			result, err := op.SaveConfig(ctx, connector.ExecuteOptions{MaxOutputBytes: b.remaining})
			if limitErr := b.record(result); err == nil {
				err = limitErr
			}
			if err != nil {
				return err
			}
			if len(result.Steps()) == 0 {
				return ErrPersistence
			}
		case "asa":
			step, err := b.command(ctx, op, "write memory")
			if err != nil {
				return err
			}
			if err := confirmASA(step); err != nil {
				return err
			}
		case "paloalto":
			if err := s.panCommit(ctx, op, &b); err != nil {
				return err
			}
		default:
			return ErrInvalid
		}
		out = deploy.Outcome{Complete: true, Durable: true}
		return receive(ctx, deploy.Receipt{Phase: "save", Index: 0, Written: true, Confirmed: true, Durable: true, ResponseDigest: hex.EncodeToString(b.digest.Sum(nil))})
	})
	return
}

func (s *Session) panCommit(ctx context.Context, op *connector.Operation, b *responseBudget) error {
	if _, err := b.command(ctx, op, "configure"); err != nil {
		return err
	}
	step, err := b.command(ctx, op, "commit")
	if err != nil {
		return err
	}
	text, err := persistenceText(step)
	if err != nil {
		return err
	}
	jobs := append(panEnqueued.FindAllStringSubmatch(text, -1), panProgress.FindAllStringSubmatch(text, -1)...)
	if len(jobs) != 1 {
		return ErrPersistence
	}
	job := jobs[0][1]
	if _, err := strconv.ParseUint(job, 10, 32); err != nil {
		return ErrPersistence
	}
	if _, err := b.command(ctx, op, "exit"); err != nil {
		return err
	}
	timer := time.NewTimer(s.options.PollInterval)
	defer timer.Stop()
	for n := 0; n < s.options.MaxPolls; n++ {
		if n > 0 {
			timer.Reset(s.options.PollInterval)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
		step, err := b.command(ctx, op, "show jobs id "+job)
		if err != nil {
			return err
		}
		text, err := persistenceText(step)
		if err != nil {
			return err
		}
		finished, err := panJob(text, job)
		if err != nil {
			return err
		}
		if finished {
			return nil
		}
	}
	return ErrPersistence
}

func panJob(text, job string) (bool, error) {
	matched, finished := 0, false
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[3] != job {
			continue
		}
		if _, err := time.Parse("2006/01/02", fields[0]); err != nil {
			continue
		}
		if _, err := time.Parse("15:04:05", fields[1]); err != nil {
			continue
		}
		if _, err := time.Parse("15:04:05", fields[2]); err != nil {
			return false, ErrPersistence
		}
		matched++
		if fields[4] != "Commit" {
			return false, ErrPersistence
		}
		switch fields[5] {
		case "FIN":
			if fields[6] != "OK" || len(fields) != 8 {
				return false, ErrPersistence
			}
			if _, err := time.Parse("15:04:05", fields[7]); err != nil {
				return false, ErrPersistence
			}
			finished = true
		case "ACT", "PEND":
			if fields[6] != "PEND" {
				return false, ErrPersistence
			}
		default:
			return false, ErrPersistence
		}
	}
	if matched != 1 {
		return false, ErrPersistence
	}
	return finished, nil
}
