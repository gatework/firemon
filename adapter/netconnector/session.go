// Package netconnector adapts a privately supplied device connection to firemon.
package netconnector

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/go-net-connector/connector"
)

var (
	ErrRetired           = errors.New("netconnector: session retired")
	ErrBusy              = errors.New("netconnector: session busy")
	ErrInvalid           = errors.New("netconnector: invalid input")
	ErrPersistence       = errors.New("netconnector: persistence not confirmed")
	ErrCapture           = errors.New("netconnector: configuration capture incomplete")
	ErrLimit             = errors.New("netconnector: resource limit exceeded")
	ErrConfigurationLock = errors.New("netconnector: configuration ownership not established")
	ErrCandidate         = errors.New("netconnector: uncommitted candidate configuration")
)

// Options bounds each operation, including the complete PAN commit polling loop.
// Zero fields select defaults. No operation retries a configuration write.
type Options struct {
	PollInterval   time.Duration
	MaxPolls       int
	Timeout        time.Duration
	MaxOutputBytes int64
	// ExclusivePANAdmin attests that the host reserves this PAN administrator
	// account for this deployment, across all tools and login sessions. PAN
	// config locks are administrator-scoped, not session-scoped; without this
	// external guarantee the adapter cannot safely edit or remove its lock.
	ExclusivePANAdmin bool
}

// Session owns its Device. Do not share that Device with other callers or copy
// Session. Close is terminal and interrupts I/O without waiting for callbacks.
type Session struct {
	device             *connector.Device
	metadata           fm.Metadata
	options            Options
	mu                 sync.Mutex
	active, closed     bool
	cancel             context.CancelFunc
	configurationToken string
	srxExclusive       bool
}

var _ deploy.Session = (*Session)(nil)

// New transfers ownership on success. The caller retains ownership on error.
func New(device *connector.Device, metadata fm.Metadata, options Options) (*Session, error) {
	if device == nil || strings.TrimSpace(metadata.Device) == "" || domainVendor(metadata.Vendor) == "" || domainVendor(device.ProfileName()) != domainVendor(metadata.Vendor) {
		return nil, ErrInvalid
	}
	options, err := options.normalized()
	if err != nil {
		return nil, err
	}
	metadata.Vendor = domainVendor(metadata.Vendor)
	if metadata.Vendor == "fortinet" && !vdomName.MatchString(metadata.Context) || metadata.Vendor != "fortinet" && metadata.Context != "" {
		return nil, ErrInvalid
	}
	return &Session{device: device, metadata: metadata, options: options}, nil
}

func (options Options) normalized() (Options, error) {
	if options.PollInterval < 0 || options.PollInterval > 5*time.Second || options.MaxPolls < 0 || options.MaxPolls > 300 || options.Timeout < 0 || options.Timeout > 30*time.Minute || options.MaxOutputBytes < 0 || options.MaxOutputBytes > 16<<20 {
		return Options{}, ErrInvalid
	}
	if options.PollInterval == 0 {
		options.PollInterval = time.Second
	}
	if options.MaxPolls == 0 {
		options.MaxPolls = 120
	}
	if options.Timeout == 0 {
		options.Timeout = 5 * time.Minute
	}
	if options.MaxOutputBytes == 0 {
		options.MaxOutputBytes = 16 << 20
	}
	return options, nil
}

// domainVendor converts connector profile aliases to the seven domain vendor names.
func domainVendor(name string) string {
	switch name {
	case "asa", "cisco_asa":
		return "asa"
	case "paloalto", "palo_alto":
		return "paloalto"
	case "hillstone":
		return "hillstone"
	case "srx", "juniper":
		return "srx"
	case "netscreen", "screenos":
		return "netscreen"
	case "fortinet", "huawei":
		return name
	}
	return ""
}

func (s *Session) run(ctx context.Context, fn func(context.Context, *connector.Operation) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrRetired
	}
	if s.active {
		s.mu.Unlock()
		return ErrBusy
	}
	ctx, cancel := context.WithTimeout(ctx, s.options.Timeout)
	s.active, s.cancel = true, cancel
	s.mu.Unlock()
	returned := false
	defer func() {
		cancel()
		if !returned || err != nil {
			err = errors.Join(err, s.Close())
		}
		s.mu.Lock()
		s.active, s.cancel = false, nil
		s.mu.Unlock()
	}()
	err = s.device.WithOperation(ctx, func(op *connector.Operation) error { return fn(ctx, op) })
	returned = true
	return err
}

// Execute journals each accepted command before the next command is sent. A
// failed command retains a separate uncertain write receipt when available.
func (s *Session) Execute(ctx context.Context, commands []string, receive deploy.ReceiptFunc) (out deploy.Outcome, err error) {
	if receive == nil || len(commands) > 10000 {
		return out, ErrInvalid
	}
	script := connector.Script{Name: "firemon-apply", Commands: make([]connector.Command, len(commands))}
	bytes := 0
	for i, command := range commands {
		bytes += len(command)
		if bytes > 1<<20 || strings.TrimSpace(command) == "" || strings.ContainsAny(command, "\r\n\x00") || !utf8.ValidString(command) {
			return out, ErrInvalid
		}
		script.Commands[i] = connector.Command{Text: command, Source: "firemon-apply", Line: i + 1, Sensitive: true, OutputSensitive: true}
	}
	err = s.run(ctx, func(ctx context.Context, op *connector.Operation) error {
		b := responseBudget{remaining: s.options.MaxOutputBytes, digest: sha256.New()}
		if s.metadata.Vendor == "paloalto" {
			if err := s.verifyPANLock(ctx, op, &b); err != nil {
				return err
			}
		}
		if s.metadata.Vendor == "srx" {
			// Begin already entered exclusive mode. Preserve the lock through
			// Save, replacing only the renderer's validated outer wrapper with
			// native top commands. Both retain their indexed transport receipts.
			if !s.srxExclusive || len(script.Commands) < 2 || commands[0] != "configure" || commands[len(commands)-1] != "exit" {
				return ErrConfigurationLock
			}
			for i := 1; i < len(commands)-1; i++ {
				if !strings.HasPrefix(commands[i], "set ") && !strings.HasPrefix(commands[i], "delete ") && !strings.HasPrefix(commands[i], "insert ") {
					return ErrInvalid
				}
			}
			script.Commands[0].Text, script.Commands[len(commands)-1].Text = "top", "top"
		}
		if s.metadata.Vendor == "fortinet" {
			if err := s.fortinetContext(ctx, op, &b); err != nil {
				return err
			}
		}
		accepted := 0
		if b.remaining <= 0 {
			return ErrLimit
		}
		var callbackErr error
		result, execErr := op.ExecuteScript(ctx, script, connector.ExecuteOptions{
			MaxOutputBytes: b.remaining,
			OnStep: func(ctx context.Context, step connector.StepResult) error {
				if accepted >= len(script.Commands) || step.Command().Text != script.Commands[accepted].Text || step.Command().Line != accepted+1 {
					callbackErr = ErrInvalid
					return callbackErr
				}
				r := deploy.Receipt{Phase: "apply", Index: accepted, Written: true, Confirmed: true, ResponseDigest: responseDigest(step.Raw())}
				accepted++
				callbackErr = receive(ctx, r)
				return callbackErr
			},
		})
		out.Complete = accepted == len(script.Commands)
		if execErr != nil && callbackErr == nil && accepted < len(script.Commands) {
			for _, attempt := range result.Attempts() {
				c := attempt.Command()
				if c.Source == "firemon-apply" && c.Line == accepted+1 && attempt.Written() > 0 {
					callbackErr = receive(ctx, deploy.Receipt{Phase: "apply", Index: accepted, Written: true, ResponseDigest: responseDigest(attempt.Raw())})
					break
				}
			}
		}
		if execErr == nil && !out.Complete {
			execErr = ErrCapture
		}
		return errors.Join(execErr, callbackErr)
	})
	return
}

func (s *Session) Close() error {
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	return s.device.Close()
}
