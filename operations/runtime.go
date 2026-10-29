package operations

import (
	"context"
	"time"

	"github.com/gatework/firemon/deploy"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
)

// Sessions supplies independent readers and deployment sessions.
type Sessions interface {
	deploy.Factory
	ReadOnlyFactory
}

// Options contains host-owned dependencies. No device is opened by New.
type Options struct {
	Store         deploy.Repository
	Journal       deploy.Journal
	Sessions      Sessions
	Authorizer    deploy.Authorizer
	Policy        policy.Engine
	Timeout       time.Duration
	MaxCandidates int
}

// Runtime owns the capture, design and deployment components.
type Runtime struct {
	collector  *Collector
	designer   *Designer
	deployment *deploy.Engine
}

func New(options Options) (*Runtime, error) {
	parser := vendors.Parser{}
	collector, err := NewCollector(CollectorOptions{Store: options.Store, Sessions: options.Sessions, Parser: parser, Timeout: options.Timeout})
	if err != nil {
		return nil, err
	}
	designer, err := NewDesigner(DesignerOptions{Store: options.Store, Engine: options.Policy, MaxCandidates: options.MaxCandidates, Timeout: options.Timeout})
	if err != nil {
		return nil, err
	}
	deployment, err := deploy.New(deploy.Options{Store: options.Store, Journal: options.Journal, Sessions: options.Sessions, Parser: parser, Authorizer: options.Authorizer, Timeout: options.Timeout})
	if err != nil {
		return nil, ErrInvalid
	}
	return &Runtime{collector: collector, designer: designer, deployment: deployment}, nil
}
func (r *Runtime) Collect(ctx context.Context, request CollectRequest) (CollectResult, error) {
	if err := ctx.Err(); err != nil {
		return CollectResult{}, err
	}
	if r == nil || r.collector == nil {
		return CollectResult{}, ErrInvalid
	}
	return r.collector.Collect(ctx, request)
}
func (r *Runtime) Design(ctx context.Context, device string, requests []policy.Request) (DesignResult, error) {
	if err := ctx.Err(); err != nil {
		return DesignResult{}, err
	}
	if r == nil || r.designer == nil {
		return DesignResult{}, ErrInvalid
	}
	return r.designer.Design(ctx, device, requests)
}
func (r *Runtime) Apply(ctx context.Context, operation, expected string, p *plan.Plan) (deploy.Result, error) {
	if err := ctx.Err(); err != nil {
		return deploy.Result{}, err
	}
	if r == nil || r.deployment == nil {
		return deploy.Result{}, ErrInvalid
	}
	return r.deployment.Apply(ctx, operation, expected, p)
}
func (r *Runtime) Recover(ctx context.Context, operation string, p *plan.Plan) (deploy.Result, error) {
	if err := ctx.Err(); err != nil {
		return deploy.Result{}, err
	}
	if r == nil || r.deployment == nil {
		return deploy.Result{}, ErrInvalid
	}
	return r.deployment.Recover(ctx, operation, p)
}
