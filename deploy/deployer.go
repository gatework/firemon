package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gatework/go-netops/apply"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// Deployment check failures.
var (
	// ErrDrift reports a device whose configuration changed since design.
	ErrDrift = errors.New("deploy: running configuration differs from the plan baseline")
	// ErrNotApplied reports a readback that still needs changes.
	ErrNotApplied = errors.New("deploy: readback still needs changes")
	// ErrUnexpectedReadback reports a readback that differs from the
	// configuration the plan predicts, for example after a device-side merge.
	ErrUnexpectedReadback = errors.New("deploy: readback differs from the planned configuration")
	// ErrNothingToDeploy reports a plan without changes or not verified.
	ErrNothingToDeploy = errors.New("deploy: plan has no verified changes")
)

// Opener lends one device session that reads parsed configurations and
// writes commands.
type Opener = apply.Opener[*firemon.Config]

// Writer renders a plan into the commands a deployment session sends.
// Deploy renders the plan itself, so the commands sent are always the
// verified plan's.
type Writer interface {
	Commands(plan *design.Plan) ([]string, error)
}

// WriterFunc adapts a function to Writer.
type WriterFunc func(plan *design.Plan) ([]string, error)

// Commands implements Writer.
func (f WriterFunc) Commands(plan *design.Plan) ([]string, error) { return f(plan) }

// Options configures a Deployer.
type Options struct {
	// Writer renders plans into device commands; it is required.
	Writer Writer
	// Journal records every state transition; it is required.
	Journal apply.Journal
	// Classify maps session errors to safe diagnostic codes.
	Classify apply.Classifier
	// Now supplies the instant schedules are evaluated at during checks.
	Now func() time.Time
}

// Deployer applies plans through one opener.
type Deployer struct {
	open     Opener
	write    Writer
	journal  apply.Journal
	classify apply.Classifier
	now      func() time.Time
}

// New returns a deployer.
func New(open Opener, opts Options) *Deployer {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Deployer{open: open, write: opts.Writer, journal: opts.Journal, classify: opts.Classify, now: now}
}

// Request is one deployment.
type Request struct {
	Plan   *design.Plan
	Device apply.Device
}

// Receipt is the terminal journal state.
type Receipt struct {
	State             apply.State
	ReportUnconfirmed bool
	Interrupted       bool
}

// Deploy applies req. The error is nil only when the readback verified.
func (d *Deployer) Deploy(ctx context.Context, req Request) (Receipt, error) {
	if req.Plan == nil || !req.Plan.Verified || len(req.Plan.Changes) == 0 {
		return Receipt{}, ErrNothingToDeploy
	}
	if req.Plan.Kind != design.PlanKindAccess && req.Plan.Kind != design.PlanKindCleanup {
		return Receipt{}, fmt.Errorf("deploy: %s plans are not deployed", req.Plan.Kind)
	}
	if d.journal == nil || d.write == nil {
		return Receipt{}, errors.New("deploy: journal and writer required")
	}
	commands, err := d.write.Commands(req.Plan)
	if err != nil {
		return Receipt{}, fmt.Errorf("deploy: render: %w", err)
	}
	if len(commands) == 0 {
		return Receipt{}, ErrNothingToDeploy
	}
	p := &checkedPlan{plan: req.Plan, commands: commands, now: d.now}
	res, err := apply.Run(ctx, apply.Request[*firemon.Config]{
		Plan: p,
		Identity: apply.State{
			Device: req.Device, PlanSHA256: digest(commands), PlanItem: req.Plan.Intent.Name,
			ExpectedConfigSHA256: req.Plan.Baseline,
		},
		Open:     d.open,
		Journal:  d.journal,
		Classify: d.classify,
	})
	receipt := Receipt{State: res.State, ReportUnconfirmed: res.ReportUnconfirmed, Interrupted: res.Interrupted}
	if err != nil {
		return receipt, fmt.Errorf("deploy: %w", err)
	}
	return receipt, nil
}

// checkedPlan adapts a design plan to apply.Plan.
type checkedPlan struct {
	plan     *design.Plan
	commands []string
	now      func() time.Time
}

// Commands implements apply.Plan.
func (p *checkedPlan) Commands() []string { return p.commands }

// CheckBefore implements apply.Plan: the device must still be the baseline.
func (p *checkedPlan) CheckBefore(before *firemon.Config) error {
	fw, err := firemon.Compile(before)
	if err != nil {
		return err
	}
	if fw.Fingerprint() != p.plan.Baseline {
		return ErrDrift
	}
	return nil
}

// CheckAfter implements apply.Plan: the readback must be exactly the
// baseline with the plan applied, and planning the intent on it must need
// no change.
func (p *checkedPlan) CheckAfter(before, after *firemon.Config) (string, error) {
	fw, err := firemon.Compile(after)
	if err != nil {
		return "", err
	}
	expected := before.Clone()
	if err := design.Apply(expected, p.plan.Changes); err != nil {
		return "", err
	}
	want, err := firemon.Compile(expected)
	if err != nil {
		return "", err
	}
	if want.Fingerprint() != fw.Fingerprint() {
		return "", ErrUnexpectedReadback
	}
	if p.plan.Kind == design.PlanKindCleanup {
		// The plan was verified to keep the effective policy; the readback
		// is exactly the verified configuration.
		return fw.Fingerprint(), nil
	}
	again, err := design.New(fw, design.Options{Now: p.now}).Plan(p.plan.Intent)
	if err != nil {
		return "", err
	}
	// The readback must need nothing more, and a plan that left nothing
	// blocked or undecided must now find the intent permitted.
	clean := len(p.plan.Conflicts) == 0 && len(p.plan.Unknown) == 0
	if len(again.Changes) > 0 || (clean && again.Status != design.StatusNoChange) {
		return "", ErrNotApplied
	}
	return fw.Fingerprint(), nil
}

func digest(commands []string) string {
	sum := sha256.Sum256([]byte(strings.Join(commands, "\n")))
	return hex.EncodeToString(sum[:])
}
