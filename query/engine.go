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
	bridges   bool // some zone forwards at layer 2
	pre       []natEntry
	// appPorts are the standard ports of the applications of the rules that
	// match any service with applications all known to the port book.
	appPorts map[*firemon.Rule]traffic.ServiceSet
}

// New returns an engine for fw.
func New(fw *firemon.Firewall, opts Options) *Engine {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	e := &Engine{
		fw: fw, rules: fw.Rules(), now: now,
		max: positiveOr(opts.MaxSpaces, DefaultMaxSpaces), maxPaths: positiveOr(opts.MaxPaths, DefaultMaxPaths),
		schedules: opts.Schedules, bridges: fw.Bridges(),
	}
	e.pre = e.preEntries()
	e.appPorts = applicationPorts(fw, e.rules)
	return e
}

// applicationPorts collects, for every rule that matches any service but
// only some applications, the union of those applications' standard ports;
// a rule naming an application the book does not know is left out and
// stays a possible match on every port.
func applicationPorts(fw *firemon.Firewall, rules []*firemon.Rule) map[*firemon.Rule]traffic.ServiceSet {
	out := map[*firemon.Rule]traffic.ServiceSet{}
	for _, r := range rules {
		apps := r.Applications()
		if len(apps) == 0 || r.ApplicationDefault() || !r.Bound().Service.IsAny() {
			continue
		}
		var ports traffic.ServiceSet
		known := true
		for _, a := range apps {
			p, ok := fw.ApplicationPorts(a)
			if !ok {
				known = false
				break
			}
			ports = ports.Union(p)
		}
		if known {
			out[r] = ports
		}
	}
	return out
}

// positiveOr returns v, or def when v is not positive.
func positiveOr(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// Firewall returns the evaluated firewall.
func (e *Engine) Firewall() *firemon.Firewall { return e.fw }

// Query evaluates req. It fails only for an empty request or an unknown
// virtual router; everything the engine cannot decide is reported in the
// result as unknown.
func (e *Engine) Query(req Request) (*Result, error) {
	if req.empty() {
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
	res := &Result{Request: req, ZonesNeeded: (req.FromZone == "" || req.ToZone == "") && e.bridges}
	res.Paths, res.Unrouted, res.Incomplete = (&search{Engine: e}).discoverTargets(req, table)
	outcomes := map[Outcome]bool{}
	if res.Incomplete {
		outcomes[OutcomeUnknown] = true
	}
	// Paths are independent: each evaluation writes only its own path.
	Each(len(res.Paths), func(i int) { e.evaluate(&res.Paths[i], at) })
	for i := range res.Paths {
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
