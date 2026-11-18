package workflow

import (
	"context"
	"time"

	"github.com/gatework/go-netops/apply"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/internal/bootstrap"
)

// Proposal is a designed and rendered change.
type Proposal struct {
	Plan   *design.Plan
	Script design.Script
}

// Propose designs and renders the change that permits intent.
func Propose(fw *firemon.Firewall, p bootstrap.Platform, intent design.Intent, now func() time.Time) (Proposal, error) {
	plan, err := design.New(fw, design.Options{Now: now}).Plan(intent)
	if err != nil {
		return Proposal{}, err
	}
	script, err := p.Render(plan)
	if err != nil {
		return Proposal{}, err
	}
	return Proposal{Plan: plan, Script: script}, nil
}

// Target is a device that lends deployment sessions and persists changes.
type Target interface {
	Open(ctx context.Context, run func(context.Context, apply.Session[*firemon.Config]) error) (opErr, cleanupErr error)
	Save(ctx context.Context) error
	Device() apply.Device
}

// Apply deploys a proposal, then persists it once the readback verified.
func Apply(ctx context.Context, t Target, p bootstrap.Platform, prop Proposal, journal apply.Journal, now func() time.Time) (deploy.Receipt, error) {
	d := deploy.New(t.Open, deploy.Options{Journal: journal, Now: now})
	receipt, err := d.Deploy(ctx, deploy.Request{Plan: prop.Plan, Commands: p.DeployCommands(prop.Script), Device: t.Device()})
	if err != nil {
		return receipt, err
	}
	return receipt, t.Save(ctx)
}
