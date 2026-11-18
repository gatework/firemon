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

// Options configures a Deployer.
type Options struct {
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
	return &Deployer{open: open, journal: opts.Journal, classify: opts.Classify, now: now}
}

// Request is one deployment.
type Request struct {
	Plan *design.Plan
	// Commands are the vendor writes, as returned by the vendor's
	// DeployCommands for the rendered script.
	Commands []string
	Device   apply.Device
}

// Receipt is the terminal journal state.
type Receipt struct {
	State             apply.State
	ReportUnconfirmed bool
	Interrupted       bool
}

// Deploy applies req. The error is nil only when the readback verified.
func (d *Deployer) Deploy(ctx context.Context, req Request) (Receipt, error) {
	if req.Plan == nil || !req.Plan.Verified || len(req.Plan.Changes) == 0 || len(req.Commands) == 0 {
		return Receipt{}, ErrNothingToDeploy
	}
	if d.journal == nil {
		return Receipt{}, errors.New("deploy: journal required")
	}
	p := &checkedPlan{plan: req.Plan, commands: req.Commands, now: d.now}
	res, err := apply.Run(ctx, apply.Request[*firemon.Config]{
		Plan: p,
		Identity: apply.State{
			Device: req.Device, PlanSHA256: digest(req.Commands), PlanItem: req.Plan.Intent.Name,
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
	again, err := design.New(fw, design.Options{Now: p.now}).Plan(p.plan.Intent)
	if err != nil {
		return "", err
	}
	if len(again.Changes) > 0 {
		return "", ErrNotApplied
	}
	return fw.Fingerprint(), nil
}

func digest(commands []string) string {
	sum := sha256.Sum256([]byte(strings.Join(commands, "\n")))
	return hex.EncodeToString(sum[:])
}
