package design

import (
	"errors"
	"fmt"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// Verification failures.
var (
	ErrNeedNotOpened  = errors.New("design: planned need is not permitted")
	ErrOutsideIntent  = errors.New("design: change permits traffic outside the intent")
	ErrConflictOpened = errors.New("design: change overrides a conflicting deny")
)

// verify applies changes to a copy of the configuration and checks the
// plan's guarantees for each need.
func (p *Planner) verify(changes []Change, intent Intent, needs []need, at time.Time) error {
	cfg := p.fw.Config()
	if err := Apply(cfg, changes); err != nil {
		return err
	}
	after, err := firemon.Compile(cfg)
	if err != nil {
		return err
	}
	if err := p.checkScope(after, needs); err != nil {
		return err
	}
	res, err := query.New(after, query.Options{Now: func() time.Time { return at }}).Query(intent.request(at))
	if err != nil {
		return err
	}
	for _, n := range needs {
		permitted := permittedOn(res, n.from, n.to)
		if !n.region.SubtractRegion(permitted).IsEmpty() {
			return fmt.Errorf("%w on %s -> %s", ErrNeedNotOpened, n.from, n.to)
		}
		for _, s := range n.conflict.Spaces() {
			if !permitted.Intersect(s).IsEmpty() {
				return fmt.Errorf("%w on %s -> %s", ErrConflictOpened, n.from, n.to)
			}
		}
	}
	return nil
}

// checkScope verifies that every rule's newly matched packets lie inside
// the intent scope of its zone pair.
func (p *Planner) checkScope(after *firemon.Firewall, needs []need) error {
	for _, r := range after.Rules() {
		if r.Action() != firemon.ActionPermit {
			continue
		}
		before, existed := p.fw.Rule(r.ID())
		added := []traffic.Space{r.Match()}
		if existed {
			added = r.Match().Subtract(before.Match())
		}
		if len(added) == 0 {
			continue
		}
		scope, ok := scopeOf(needs, r)
		if !ok {
			return fmt.Errorf("%w: rule %s", ErrOutsideIntent, r.ID())
		}
		for _, s := range added {
			if !scope.ContainsSpace(s) {
				return fmt.Errorf("%w: rule %s", ErrOutsideIntent, r.ID())
			}
		}
	}
	return nil
}

// scopeOf returns the intent scope of the zone pair a changed rule is
// written for.
func scopeOf(needs []need, r *firemon.Rule) (traffic.Region, bool) {
	s := r.Spec()
	if len(s.From) != 1 || len(s.To) != 1 {
		return traffic.Region{}, false
	}
	for _, n := range needs {
		if n.from == s.From[0] && n.to == s.To[0] {
			return n.scope, true
		}
	}
	return traffic.Region{}, false
}

// permittedOn returns the permitted policy space of one zone pair.
func permittedOn(res *query.Result, from, to string) traffic.Region {
	var out traffic.Region
	for i := range res.Paths {
		if res.Paths[i].From == from && res.Paths[i].To == to {
			out = out.Union(res.Paths[i].Region(query.OutcomePermit))
		}
	}
	return out
}
