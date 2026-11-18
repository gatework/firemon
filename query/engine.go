package query

import (
	"cmp"
	"fmt"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// Engine evaluates requests against one firewall. It is immutable and safe
// for concurrent use.
type Engine struct {
	fw        *firemon.Firewall
	rules     []*firemon.Rule
	now       func() time.Time
	max       int
	maxPaths  int
	schedules ScheduleMode
}

// New returns an engine for fw.
func New(fw *firemon.Firewall, opts Options) *Engine {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Engine{
		fw: fw, rules: fw.Rules(), now: now,
		max: cmp.Or(opts.MaxSpaces, DefaultMaxSpaces), maxPaths: cmp.Or(opts.MaxPaths, DefaultMaxPaths),
		schedules: opts.Schedules,
	}
}

// Firewall returns the evaluated firewall.
func (e *Engine) Firewall() *firemon.Firewall { return e.fw }

// Query evaluates req. It fails only for an empty request or an unknown
// virtual router; everything the engine cannot decide is reported in the
// result as unknown.
func (e *Engine) Query(req Request) (*Result, error) {
	if req.Src.IsEmpty() || req.Dst.IsEmpty() || req.Service.IsEmpty() {
		return nil, ErrEmptyRequest
	}
	at := req.At
	if at.IsZero() {
		at = e.now()
	}
	vr := cmp.Or(req.VirtualRouter, e.fw.Semantics().DefaultVirtualRouter)
	table, ok := e.fw.RoutingTable(vr)
	if !ok && (req.FromZone == "" || req.ToZone == "") {
		return nil, fmt.Errorf("query: unknown virtual router %q", vr)
	}
	res := &Result{Request: req}
	res.Paths, res.Unrouted, res.Incomplete = e.discover(req, table)
	outcomes := map[Outcome]bool{}
	if res.Incomplete {
		outcomes[OutcomeUnknown] = true
	}
	for i := range res.Paths {
		e.evaluate(&res.Paths[i], at)
		res.Incomplete = res.Incomplete || res.Paths[i].Incomplete
		for _, d := range res.Paths[i].Decisions {
			outcomes[d.Outcome] = true
		}
	}
	if !res.Unrouted.IsEmpty() {
		outcomes[OutcomeDefault] = true
	}
	res.Verdict = verdictOf(outcomes)
	return res, nil
}

// Evaluate runs ordered first-match on a policy space between two zones
// without path discovery. Design uses it to verify candidate changes.
func (e *Engine) Evaluate(from, to string, policy traffic.Space, at time.Time) Path {
	p := Path{From: from, To: to, Original: policy, Policy: policy}
	e.evaluate(&p, at)
	return p
}
