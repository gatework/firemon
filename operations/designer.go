package operations

import (
	"context"
	"slices"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/dependency"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

// CurrentStore supplies only a usable, unreserved current graph. Historical or
// incomplete snapshots remain available through the host's snapshot.Store.
type CurrentStore interface {
	Current(context.Context, string) (*fm.Firewall, snapshot.Head, error)
}

type DesignerOptions struct {
	Store         CurrentStore
	Engine        policy.Engine
	MaxCandidates int
	// Timeout bounds graph loading and planning. Zero uses five minutes.
	Timeout time.Duration
}

type Designer struct {
	store         CurrentStore
	engine        policy.Engine
	maxCandidates int
	timeout       time.Duration
}

func NewDesigner(options DesignerOptions) (*Designer, error) {
	if dependency.Nil(options.Store) || options.Timeout < 0 || options.MaxCandidates < 0 {
		return nil, ErrInvalid
	}
	return &Designer{store: options.Store, engine: options.Engine, maxCandidates: options.MaxCandidates, timeout: options.Timeout}, nil
}

type DesignResult struct {
	Revision string
	Plan     *plan.Plan
}

// Design returns an exact plan and the current revision required by Apply.
// Empty request scopes use the capture's selected context. Inputs are not
// mutated; an explicit scope remains subject to native query and render proof.
func (d Designer) Design(ctx context.Context, device string, requests []policy.Request) (DesignResult, error) {
	if err := ctx.Err(); err != nil {
		return DesignResult{}, err
	}
	if dependency.Nil(d.store) || strings.TrimSpace(device) == "" {
		return DesignResult{}, ErrInvalid
	}
	ctx, cancel := operationContext(ctx, d.timeout)
	defer cancel()
	fw, head, err := d.store.Current(ctx, device)
	if err != nil {
		return DesignResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return DesignResult{}, err
	}
	if fw == nil || !head.Complete || !fw.Complete() {
		return DesignResult{}, snapshot.ErrUnavailable
	}
	if fw.Metadata().Device != device || head.Revision == "" || head.SemanticDigest != fw.SemanticDigest() {
		return DesignResult{}, ErrInvalid
	}
	renderer, err := vendors.Renderer(fw.Metadata().Vendor)
	if err != nil {
		return DesignResult{}, err
	}
	requests = slices.Clone(requests)
	for i := range requests {
		if requests[i].Scope == "" {
			requests[i].Scope = fw.Metadata().Context
		}
	}
	p, err := (plan.Planner{Renderer: renderer, Engine: d.engine, MaxCandidates: d.maxCandidates}).Plan(ctx, fw, requests)
	if err != nil {
		return DesignResult{}, err
	}
	return DesignResult{Revision: head.Revision, Plan: p}, nil
}
