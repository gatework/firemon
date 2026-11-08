package policy

import (
	"context"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// Resolver shares bounded expansion caches across requests for one immutable
// graph. It belongs to one evaluation or candidate and is not concurrent-safe.
// Each call has MaxCombinations; all calls together have MaxVisits.
type Resolver struct {
	firewall *fm.Firewall
	limits   Limits
	visits   int
	cache    resolutionCache
}

// NewResolver binds one immutable graph; unresolved declarations remain unknown.
func NewResolver(firewall *fm.Firewall, limits Limits) (*Resolver, error) {
	if firewall == nil {
		return nil, ErrInvalid
	}
	limits = limits.WithDefaults()
	return &Resolver{firewall: firewall, limits: limits, cache: resolutionCache{firewall: firewall, remaining: limits.MaxVisits}}, nil
}

// Visits reports charged resolution steps, including cached logical expansion
// costs and work completed before an error. It never decreases.
func (r *Resolver) Visits() int {
	if r == nil {
		return 0
	}
	return r.visits
}

// RestrictVisits caps future resolution work at remaining visits. It never
// increases an earlier allowance, including for cached results. Zero exhausts
// the allowance; a negative count or uninitialized resolver is invalid.
// Callers sharing a larger budget must restrict before resolving, then deduct
// the change in Visits from that budget, including when resolution fails.
func (r *Resolver) RestrictVisits(remaining int) error {
	if r == nil || r.firewall == nil || remaining < 0 {
		return ErrInvalid
	}
	if remaining < r.limits.MaxVisits-r.visits {
		r.limits.MaxVisits = r.visits + remaining
	}
	return nil
}

func (r *Resolver) budget(ctx context.Context) (*resolutionBudget, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || r.firewall == nil {
		return nil, ErrInvalid
	}
	remaining := r.limits.MaxVisits - r.visits
	if remaining <= 0 {
		return nil, ErrBudget
	}
	return &resolutionBudget{ctx: ctx, limit: min(r.limits.MaxCombinations, remaining), cache: &r.cache}, nil
}

// Addresses returns exact coverage or conservative unknown evidence. Errors
// return no partial coverage, and cached results consume the same logical budget.
func (r *Resolver) Addresses(ctx context.Context, refs []fm.AddressRef, any bool) (flow.AddressSet, bool, error) {
	budget, err := r.budget(ctx)
	if err != nil {
		return flow.AddressSet{}, false, err
	}
	set, known, err := resolveAddresses(r.firewall, refs, any, budget)
	r.visits += budget.spent
	if err != nil {
		return flow.AddressSet{}, false, err
	}
	return set, known, nil
}

// Services preserves complete service tuples and returns an owned container,
// including when a bounded expansion is reused from this resolver's cache.
func (r *Resolver) Services(ctx context.Context, refs []fm.ServiceRef, any bool) ([]fm.ServiceTerm, bool, error) {
	budget, err := r.budget(ctx)
	if err != nil {
		return nil, false, err
	}
	terms, known, err := resolveServices(r.firewall, refs, any, budget)
	r.visits += budget.spent
	if err != nil {
		return nil, false, err
	}
	return slices.Clone(terms), known, nil
}
