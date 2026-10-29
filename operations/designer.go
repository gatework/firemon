package operations

import (
	"context"
	"slices"
	"strings"
	"time"

	fm "github.com/gatework/firemon"
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

type Designer struct {
	Store         CurrentStore
	Engine        policy.Engine
	MaxCandidates int
	// Timeout bounds graph loading and planning. Zero uses five minutes.
	Timeout time.Duration
}

type DesignResult struct {
	Revision string
	Plan     *plan.Plan
}

// Design returns an exact plan and the current revision required by Apply.
// Empty request scopes use the capture's selected context. Inputs are not
// mutated; an explicit scope remains subject to native query and render proof.
func (d Designer) Design(ctx context.Context, device string, requests []policy.Request) (DesignResult, error) {
	if d.Store == nil || strings.TrimSpace(device) == "" {
		return DesignResult{}, ErrInvalid
	}
	ctx, cancel := operationContext(ctx, d.Timeout)
	defer cancel()
	fw, head, err := d.Store.Current(ctx, device)
	if err != nil {
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
	p, err := (plan.Planner{Renderer: renderer, Engine: d.Engine, MaxCandidates: d.MaxCandidates}).Plan(ctx, fw, requests)
	if err != nil {
		return DesignResult{}, err
	}
	return DesignResult{Revision: head.Revision, Plan: p}, nil
}
