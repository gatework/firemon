package deploy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gatework/netops/apply"
	"github.com/gatework/netops/change"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/failure"

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
// writes commands. It reports the operation and close errors separately.
type Opener func(ctx context.Context, run func(context.Context, apply.Session[*firemon.Config]) error) (opErr, closeErr error)

// Executions persists the execution record of a plan on a device. The
// netops store/journal.Journal implements it.
type Executions interface {
	Execution(planID, deviceID string) apply.Journal
}

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
	Journal Executions
	// Now supplies the instant schedules are evaluated at during checks.
	Now func() time.Time
}

// Deployer applies plans through one opener.
type Deployer struct {
	open    Opener
	write   Writer
	journal Executions
	now     func() time.Time
}

// New returns a deployer.
func New(open Opener, opts Options) *Deployer {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Deployer{open: open, write: opts.Writer, journal: opts.Journal, now: now}
}

// Request is one deployment.
type Request struct {
	Plan   *design.Plan
	Device device.Device
}

// Receipt is the terminal journal state.
type Receipt struct {
	Record apply.Record
	// ReportUnconfirmed is set when the final record could not be
	// persisted or the session did not close cleanly after a write.
	ReportUnconfirmed bool
	Interrupted       bool
}

// Deploy applies req in one session. The error is nil only when the
// readback verified.
func (d *Deployer) Deploy(ctx context.Context, req Request) (Receipt, error) {
	if req.Plan == nil || !req.Plan.Verified || len(req.Plan.Changes) == 0 {
		return Receipt{}, ErrNothingToDeploy
	}
	if req.Plan.Kind != design.PlanKindAccess && req.Plan.Kind != design.PlanKindCleanup {
		return Receipt{}, fmt.Errorf("deploy: %s plans are not deployed", req.Plan.Kind)
	}
	if d.journal == nil || d.write == nil || d.open == nil {
		return Receipt{}, errors.New("deploy: opener, journal and writer required")
	}
	commands, err := d.write.Commands(req.Plan)
	if err != nil {
		return Receipt{}, fmt.Errorf("deploy: render: %w", err)
	}
	if len(commands) == 0 {
		return Receipt{}, ErrNothingToDeploy
	}
	p, err := newCheckedPlan(req, commands, d.now)
	if err != nil {
		return Receipt{}, err
	}
	var rec apply.Record
	var execution apply.Journal
	opErr, closeErr := d.open(ctx, func(ctx context.Context, s apply.Session[*firemon.Config]) error {
		execution = d.journal.Execution(p.meta.ID, p.target.ID)
		var runErr error
		rec, runErr = apply.Run(ctx, apply.Request[*firemon.Config]{
			Plan: p, Session: s, Journal: execution, Now: d.now,
		})
		return runErr
	})
	var closeChanged bool
	if rec.Status == "" {
		// The session never opened: nothing was journaled or sent.
		rec.Status, rec.Failure = apply.StatusFailed, failure.Primary(opErr)
	} else {
		// A close failure after the run can make success uncertain: the
		// journal must hold the settled record, not the run's last one.
		rec, closeChanged = apply.Settle(rec, closeErr)
		if closeChanged {
			pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), apply.DefaultPersistTimeout)
			if err := execution.Write(pctx, rec); err != nil {
				rec.Unconfirmed = true
				closeErr = errors.Join(closeErr, failure.Wrap(failure.CodeStorage, "journal: settle", err))
			}
			cancel()
		}
	}
	receipt := Receipt{Record: rec, ReportUnconfirmed: rec.Unconfirmed || closeChanged, Interrupted: failure.Cancelled(opErr)}
	if err := errors.Join(opErr, closeErr); err != nil || !rec.Status.Success() {
		return receipt, fmt.Errorf("deploy: %s: %w", rec.Status, errors.Join(err, failure.New(rec.Failure, "deploy")))
	}
	return receipt, nil
}

// checkedPlan adapts a design plan to apply.Plan.
type checkedPlan struct {
	plan     *design.Plan
	meta     change.Meta
	target   device.Device
	commands []change.Command
	now      func() time.Time
}

func newCheckedPlan(req Request, commands []string, now func() time.Time) (*checkedPlan, error) {
	d := digest(commands)
	p := &checkedPlan{
		plan: req.Plan, target: req.Device.Clone(), commands: change.Commands(commands...), now: now,
		meta: change.Meta{ID: "firemon-" + string(d)[:16], Reason: req.Plan.Intent.Name, Created: now().UTC()},
	}
	for _, c := range p.commands {
		if strings.TrimSpace(c.Text) == "" || strings.ContainsAny(c.Text, "\r\n\x00") {
			return nil, fmt.Errorf("deploy: render: command %q is not one line", c.Text)
		}
	}
	return p, nil
}

// Meta implements apply.Plan.
func (p *checkedPlan) Meta() change.Meta { return p.meta }

// Target implements apply.Plan.
func (p *checkedPlan) Target() device.Device { return p.target.Clone() }

// Baseline implements apply.Plan: the fingerprint the plan was designed on.
func (p *checkedPlan) Baseline() evidence.Digest { return fingerprint(p.plan.Baseline) }

// Digest implements apply.Plan.
func (p *checkedPlan) Digest() (evidence.Digest, error) {
	texts := make([]string, len(p.commands))
	for i, c := range p.commands {
		texts[i] = c.Text
	}
	return digest(texts), nil
}

// Commands implements apply.Plan.
func (p *checkedPlan) Commands() []change.Command { return slices.Clone(p.commands) }

// Precheck implements apply.Plan: the device must still be the baseline.
func (p *checkedPlan) Precheck(before *firemon.Config) (change.Readiness, error) {
	fw, err := firemon.Compile(before)
	if err != nil {
		return 0, err
	}
	if fw.Fingerprint() != p.plan.Baseline {
		return 0, failure.Wrap(failure.CodeDrifted, "deploy", ErrDrift)
	}
	if err := p.plan.VerifyBefore(fw, p.now()); err != nil {
		return 0, failure.Wrap(failure.CodeDrifted, "deploy", err)
	}
	return change.Ready, nil
}

// Verify implements apply.Plan: the readback must be exactly the baseline
// with the plan applied, and planning the intent on it must need no change.
func (p *checkedPlan) Verify(before, after *firemon.Config) (evidence.Digest, error) {
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
		return "", failure.Wrap(failure.CodeUnconfirmed, "deploy", ErrUnexpectedReadback)
	}
	if err := p.plan.VerifyResult(fw, p.now()); err != nil {
		return "", failure.Wrap(failure.CodeUnconfirmed, "deploy", fmt.Errorf("%w: %w", ErrNotApplied, err))
	}
	return fingerprint(fw.Fingerprint()), nil
}

// fingerprint returns a firemon fingerprint as a digest, hashing it when it
// is not already a hex SHA-256.
func fingerprint(fp string) evidence.Digest {
	if d := evidence.Digest(fp); d.Valid() {
		return d
	}
	return evidence.DigestString(fp)
}

func digest(commands []string) evidence.Digest {
	return evidence.DigestString(strings.Join(commands, "\n"))
}
