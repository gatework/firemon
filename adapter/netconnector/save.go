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
		case "hillstone", "huawei":
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
			if err := s.verifyPANLock(ctx, op, &b); err != nil {
				return err
			}
			if err := s.panCommit(ctx, op, &b); err != nil {
				return err
			}
		case "srx":
			if !s.srxExclusive {
				return ErrConfigurationLock
			}
			step, err := b.command(ctx, op, `commit comment "firemon:`+s.configurationToken+`"`)
			if err != nil {
				return err
			}
			text, err := persistenceText(step)
			if err != nil {
				return err
			}
			complete := 0
			for _, line := range strings.Split(text, "\n") {
				if strings.TrimSpace(line) == "commit complete" {
					complete++
				}
			}
			if complete != 1 {
				return ErrPersistence
			}
		case "netscreen":
			step, err := b.command(ctx, op, "save")
			if err != nil {
				return err
			}
			if _, err := persistenceText(step); err != nil {
				return err
			}
			// ScreenOS save may return only the prompt. Establish persistence
			// by comparing fresh native running and flash views, never a prompt.
			current, err := b.command(ctx, op, "get config")
			if err != nil {
				return err
			}
			saved, err := b.command(ctx, op, "get config saved")
			if err != nil {
				return err
			}
			body := configBody(current.Output(), current.Command().Text, current.Prompt())
			if body == "" || body != configBody(saved.Output(), saved.Command().Text, saved.Prompt()) {
				return ErrPersistence
			}
		case "fortinet":
			if err := s.fortinetAutomatic(ctx, op, &b); err != nil {
				return err
			}
			step, err := b.command(ctx, op, "execute cfg save")
			if err != nil {
				return err
			}
			if _, err := persistenceText(step); err != nil {
				return err
			}
			if err := s.fortinetAutomatic(ctx, op, &b); err != nil {
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
	if _, err := strconv.ParseUint(job, 10, 32); err != nil || job == "0" {
		return false, ErrPersistence
	}
	if failure.MatchString(text) {
		return false, ErrPersistence
	}
	matched, finished := 0, false
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if _, err := time.Parse("2006/01/02", f[0]); err != nil {
			continue
		}
		// Native rows have optional Dequeued and PositionInQ columns. Parse from
		// both ends, where Type/Status/Result/Completed remain unambiguous.
		if len(f) < 7 || len(f) > 9 {
			return false, ErrPersistence
		}
		if _, err := time.Parse("15:04:05", f[1]); err != nil {
			return false, ErrPersistence
		}
		i := 2
		hasDequeue := strings.Contains(f[i], ":")
		if hasDequeue {
			if _, err := time.Parse("15:04:05", f[i]); err != nil {
				return false, ErrPersistence
			}
			i++
		}
		if f[i] != job {
			return false, ErrPersistence
		}
		i++
		if len(f)-i == 5 {
			if n, err := strconv.ParseUint(f[i], 10, 32); err != nil || n == 0 {
				return false, ErrPersistence
			}
			i++
		}
		if len(f)-i != 4 || f[i] != "Commit" {
			return false, ErrPersistence
		}
		status, result, progress := f[i+1], f[i+2], f[i+3]
		matched++
		switch status {
		case "FIN":
			if !hasDequeue || result != "OK" {
				return false, ErrPersistence
			}
			if _, err := time.Parse("15:04:05", progress); err != nil {
				return false, ErrPersistence
			}
			finished = true
		case "QUEUED", "PEND", "ACT":
			if result != "PEND" || status == "ACT" && !hasDequeue {
				return false, ErrPersistence
			}
			if strings.HasSuffix(progress, "%") {
				n, err := strconv.ParseUint(strings.TrimSuffix(progress, "%"), 10, 8)
				if err != nil || n > 100 {
					return false, ErrPersistence
				}
			} else if _, err := time.Parse("15:04:05", progress); err != nil {
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
