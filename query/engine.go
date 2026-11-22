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
	activity  func(*firemon.Rule) Activity
	bridges   bool // some zone forwards at layer 2
	pre       []natEntry
	// appPorts bounds application-default rules whose applications all
	// have known standard ports.
	appPorts map[*firemon.Rule]traffic.ServiceSet
	// appRules are the rules restricted to applications, in order.
	appRules []*firemon.Rule
	// unknownApps marks application rules naming an application neither
	// the book nor a group knows: on unidentified ports they may match.
	unknownApps map[*firemon.Rule]bool
	// urlRules reports rules by URL category, which identification
	// settles for traffic that is not web.
	urlRules bool
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
		schedules: opts.Schedules, activity: opts.Activity, bridges: fw.Bridges(),
	}
	e.pre = e.preEntries()
	e.appPorts = applicationPorts(fw, e.rules)
	for _, r := range e.rules {
		if len(r.Applications()) > 0 {
			e.appRules = append(e.appRules, r)
		}
		e.urlRules = e.urlRules || len(firemon.ConditionValues(r.Spec().Conditions, firemon.ConditionURLCategory)) > 0
		for _, a := range r.Applications() {
			if !fw.KnowsApplication(a) {
				if e.unknownApps == nil {
					e.unknownApps = map[*firemon.Rule]bool{}
				}
				e.unknownApps[r] = true
			}
		}
	}
	return e
}

// applicationPorts collects the port bound explicitly requested by each
// application-default rule. An incomplete port book cannot bound the rule.
func applicationPorts(fw *firemon.Firewall, rules []*firemon.Rule) map[*firemon.Rule]traffic.ServiceSet {
	out := map[*firemon.Rule]traffic.ServiceSet{}
	for _, r := range rules {
		apps := r.Applications()
		if !r.DefaultPorts() || len(apps) == 0 {
			continue
		}
		var ports traffic.ServiceSet
		known := true
		for _, a := range apps {
			p, ok := fw.ApplicationPorts(a)
			if !ok || p.IsEmpty() {
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
	for i := range res.Paths {
		res.Paths[i].users, res.Paths[i].urlCategories, res.Paths[i].strict = req.Users, req.URLCategories, req.Strict
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
