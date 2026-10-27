// Package plan selects deterministic, renderable policy changes with exact traffic proofs.
package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"net/netip"
	"slices"
	"strings"
	"time"
)

var ErrUnsafe = errors.New("no proven renderable policy plan")

type ChangeKind uint8

const (
	AppendMembers ChangeKind = iota + 1
	CreateRule
	RemoveRule
)

type Change struct {
	Kind                  ChangeKind
	Rule                  fm.ID
	Sources, Destinations []fm.AddressRef
	Services              []fm.ServiceRef
}
type Cost struct {
	NewRules, AppendedMembers, NewObjects, ModifiedRules, Moves, Position int
	ID                                                                    string
}

func (c Cost) less(b Cost) bool {
	aValues := []int{c.NewRules, c.AppendedMembers, c.NewObjects, c.ModifiedRules, c.Moves, c.Position}
	bValues := []int{b.NewRules, b.AppendedMembers, b.NewObjects, b.ModifiedRules, b.Moves, b.Position}
	for i, a := range aValues {
		if a != bValues[i] {
			return a < bValues[i]
		}
	}
	return c.ID < b.ID
}

type Proof struct {
	BaseDigest, ResultDigest                      string
	TargetAllowed, OutsidePreserved, NATUnchanged bool
	TargetSatisfied                               bool
}
type Plan struct {
	before, after *fm.Firewall
	changes       []Change
	commands      []string
	cost          Cost
	proof         Proof
	digest        string
	target        policy.Request
	engine        policy.Engine
	preservation  *policy.Equivalence
	transfers     []RuleIntent
	transferFrom  time.Time
}

func (p *Plan) Before() *fm.Firewall { return p.before }
func (p *Plan) After() *fm.Firewall  { return p.after }
func (p *Plan) Changes() []Change {
	out := slices.Clone(p.changes)
	for i := range out {
		out[i].Sources = slices.Clone(out[i].Sources)
		out[i].Destinations = slices.Clone(out[i].Destinations)
		out[i].Services = slices.Clone(out[i].Services)
	}
	return out
}
func (p *Plan) Commands() []string { return slices.Clone(p.commands) }
func (p *Plan) Cost() Cost         { return p.cost }
func (p *Plan) Proof() Proof       { return p.proof }
func (p *Plan) Digest() string     { return p.digest }

type Renderer interface {
	Render(context.Context, *fm.Firewall, *fm.Firewall, []Change) ([]string, error)
}
type Planner struct {
	Renderer      Renderer
	MaxCandidates int
	Engine        policy.Engine
}

func (p Planner) Plan(ctx context.Context, fw *fm.Firewall, requests []policy.Request) (*Plan, error) {
	if fw == nil || !fw.Complete() || len(requests) == 0 || len(requests) > 100 {
		return nil, ErrUnsafe
	}
	maxCandidates := p.MaxCandidates
	if maxCandidates <= 0 {
		maxCandidates = 128
	}
	q := requests[0]
	if q.RuleSet == "" {
		q.RuleSet = "security"
	}
	for _, r := range requests[1:] {
		rs := r.RuleSet
		if rs == "" {
			rs = "security"
		}
		if r.Scope != q.Scope || rs != q.RuleSet || r.FromZone != q.FromZone || r.ToZone != q.ToZone || !r.At.Equal(q.At) || r.EgressInterface != q.EgressInterface {
			return nil, fmt.Errorf("%w: batch contexts differ", ErrUnsafe)
		}
		var err error
		q.Traffic, err = q.Traffic.Union(r.Traffic, 4096)
		if err != nil {
			return nil, err
		}
	}
	evaluation, err := p.Engine.Query(ctx, fw, q)
	if err != nil {
		return nil, err
	}
	if !evaluation.Complete || !evaluation.Unknown.Empty() {
		return nil, ErrUnsafe
	}
	gap, err := q.Traffic.Difference(evaluation.Allowed, 4096)
	if err != nil {
		return nil, err
	}
	if gap.Empty() {
		result := &Plan{before: fw, after: fw, proof: Proof{BaseDigest: fw.SemanticDigest(), ResultDigest: fw.SemanticDigest(), TargetAllowed: true, OutsidePreserved: true, NATUnchanged: true}}
		result.target, result.engine = q, p.Engine
		if err := result.seal(); err != nil {
			return nil, err
		}
		return result, nil
	}
	if p.Renderer == nil {
		return nil, fmt.Errorf("%w: renderer required", ErrUnsafe)
	}
	// A permanent change cannot be proven across unmodeled time or condition transitions.
	for _, r := range fw.Rules() {
		v := r.Record()
		if v.Match.Schedule != "" || len(v.Match.Applications) > 0 || len(v.Match.Users) > 0 {
			return nil, ErrUnsafe
		}
	}
	var candidates []*Plan
	visits := 0
	for _, rule := range fw.Rules() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		visits++
		if visits > 100000 {
			return nil, policy.ErrBudget
		}
		r := rule.Record()
		if r.Disabled || r.Builtin || r.Action != fm.Permit || r.Scope != q.Scope || r.RuleSet != q.RuleSet || r.Log == fm.Unknown || !sameZones(r.Match, q) {
			continue
		}
		next, changes, cost, err := appendCandidate(fw, r, gap)
		if err != nil {
			continue
		}
		if len(changes) == 0 {
			continue
		}
		if len(candidates) >= maxCandidates {
			return nil, policy.ErrBudget
		}
		candidates = append(candidates, &Plan{before: fw, after: next, changes: changes, cost: cost})
	}
	next, changes, cost, err := createCandidate(fw, q, gap)
	if err != nil {
		return nil, err
	}
	if len(candidates) >= maxCandidates {
		return nil, policy.ErrBudget
	}
	candidates = append(candidates, &Plan{before: fw, after: next, changes: changes, cost: cost})
	slices.SortStableFunc(candidates, func(a, b *Plan) int {
		if a.cost.less(b.cost) {
			return -1
		}
		if b.cost.less(a.cost) {
			return 1
		}
		return 0
	})
	for _, candidate := range candidates {
		proof, err := p.prove(ctx, fw, candidate.after, q)
		if err != nil {
			if errors.Is(err, policy.ErrBudget) || errors.Is(err, flow.ErrBudget) || ctx.Err() != nil {
				return nil, err
			}
			continue
		}
		commands, err := p.Renderer.Render(ctx, fw, candidate.after, candidate.Changes())
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if len(commands) == 0 {
			continue
		}
		candidate.proof = proof
		candidate.commands = slices.Clone(commands)
		candidate.target, candidate.engine = q, p.Engine
		if err := candidate.seal(); err != nil {
			return nil, err
		}
		return candidate, nil
	}
	return nil, ErrUnsafe
}
func sameZones(m fm.Match, q policy.Request) bool {
	from := q.FromZone == "" && m.AnyFromZone || !m.AnyFromZone && len(m.FromZones) == 1 && m.FromZones[0] == q.FromZone
	to := q.ToZone == "" && m.AnyToZone || !m.AnyToZone && len(m.ToZones) == 1 && m.ToZones[0] == q.ToZone
	return from && to
}
func universe() flow.Traffic {
	full := flow.Interval{Low: 0, High: 65535}
	octet := flow.Interval{Low: 0, High: 255}
	var boxes []flow.Box
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		r, _ := flow.PrefixRange(netip.MustParsePrefix(cidr))
		boxes = append(boxes, flow.Box{Source: r, Destination: r, Protocol: octet, SourcePort: full, DestinationPort: full, ICMPType: octet, ICMPCode: octet})
	}
	result, _ := flow.NewTraffic(4096, boxes...)
	return result
}
func equal(a, b flow.Traffic) (bool, error) {
	x, err := a.Difference(b, 4096)
	if err != nil || !x.Empty() {
		return false, err
	}
	x, err = b.Difference(a, 4096)
	return err == nil && x.Empty(), err
}
func (p Planner) prove(ctx context.Context, before, after *fm.Firewall, q policy.Request) (Proof, error) {
	target, err := p.Engine.Query(ctx, after, q)
	if err != nil {
		return Proof{}, err
	}
	covered, err := target.Allowed.Contains(q.Traffic, 4096)
	if err != nil {
		return Proof{}, err
	}
	if !covered || !target.Complete || !target.Unknown.Empty() {
		return Proof{}, ErrUnsafe
	}
	all := q
	all.Traffic = universe()
	prior, err := p.Engine.Query(ctx, before, all)
	if err != nil {
		return Proof{}, err
	}
	next, err := p.Engine.Query(ctx, after, all)
	if err != nil {
		return Proof{}, err
	}
	if !prior.Complete || !next.Complete {
		return Proof{}, ErrUnsafe
	}
	// Compare effective rule ownership too: equal permit coverage alone does not preserve logging/order.
	traces := make(map[fm.ID]flow.Traffic)
	for _, trace := range next.Trace {
		traces[trace.Rule] = trace.Traffic
	}
	for _, trace := range prior.Trace {
		old, err := trace.Traffic.Difference(q.Traffic, 4096)
		if err != nil {
			return Proof{}, err
		}
		new, err := traces[trace.Rule].Difference(q.Traffic, 4096)
		if err != nil {
			return Proof{}, err
		}
		same, err := equal(old, new)
		if err != nil {
			return Proof{}, err
		}
		if !same {
			return Proof{}, ErrUnsafe
		}
		delete(traces, trace.Rule)
	}
	for _, trace := range traces {
		outside, err := trace.Difference(q.Traffic, 4096)
		if err != nil {
			return Proof{}, err
		}
		if !outside.Empty() {
			return Proof{}, ErrUnsafe
		}
	}
	old, err := prior.Unmatched.Difference(q.Traffic, 4096)
	if err != nil {
		return Proof{}, err
	}
	new, err := next.Unmatched.Difference(q.Traffic, 4096)
	if err != nil {
		return Proof{}, err
	}
	same, err := equal(old, new)
	if err != nil {
		return Proof{}, err
	}
	if !same {
		return Proof{}, ErrUnsafe
	}
	return Proof{BaseDigest: before.SemanticDigest(), ResultDigest: after.SemanticDigest(), TargetAllowed: true, OutsidePreserved: true, NATUnchanged: true}, nil
}
func (p *Plan) seal() error {
	type transfer struct {
		Intent  RuleIntent
		Traffic []flow.Box
	}
	targets := make([]transfer, 0, len(p.transfers))
	for _, intent := range p.transfers {
		targets = append(targets, transfer{intent, intent.Request.Traffic.Boxes()})
	}
	b, err := json.Marshal(struct {
		Proof        Proof
		Changes      []Change
		Commands     []string
		Target       policy.Request
		Traffic      []flow.Box
		Preservation *policy.Equivalence
		Transfers    []transfer
		TransferFrom time.Time
	}{p.proof, p.changes, p.commands, p.target, p.target.Traffic.Boxes(), p.preservation, targets, p.transferFrom})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	p.digest = hex.EncodeToString(sum[:])
	return nil
}
func generatedID(prefix string, value any) fm.ID {
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return fm.ID(prefix + hex.EncodeToString(sum[:8]))
}
func ensureAddress(d *fm.Data, r flow.Range) fm.AddressRef {
	for _, a := range d.Addresses {
		if len(a.Ranges) == 1 && a.Ranges[0] == r && a.FQDN == "" && len(a.Unsupported) == 0 {
			return fm.AddressRef{Kind: fm.AddressObject, ID: a.ID}
		}
	}
	id := generatedID("fm-a-", r)
	for _, a := range d.Addresses {
		if a.ID == id {
			id += "-new"
		}
	}
	d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id, Name: string(id)}, Ranges: []flow.Range{r}})
	return fm.AddressRef{Kind: fm.AddressObject, ID: id}
}
func serviceOf(b flow.Box) fm.ServiceTerm {
	return fm.ServiceTerm{Protocol: b.Protocol, SourcePort: b.SourcePort, DestinationPort: b.DestinationPort, ICMPType: b.ICMPType, ICMPCode: b.ICMPCode}
}
func ensureService(d *fm.Data, term fm.ServiceTerm) fm.ServiceRef {
	for _, s := range d.Services {
		if len(s.Terms) == 1 && s.Terms[0] == term && len(s.Unsupported) == 0 {
			return fm.ServiceRef{Kind: fm.ServiceObject, ID: s.ID}
		}
	}
	id := generatedID("fm-s-", term)
	for _, s := range d.Services {
		if s.ID == id {
			id += "-new"
		}
	}
	d.Services = append(d.Services, fm.ServiceRecord{Object: fm.Object{ID: id, Name: string(id)}, Terms: []fm.ServiceTerm{term}})
	return fm.ServiceRef{Kind: fm.ServiceObject, ID: id}
}
func appendCandidate(fw *fm.Firewall, rule fm.RuleRecord, gap flow.Traffic) (*fm.Firewall, []Change, Cost, error) {
	d := fw.Export()
	objects := len(d.Addresses) + len(d.Services)
	change := Change{Kind: AppendMembers, Rule: rule.ID}
	src, known := policy.Addresses(fw, rule.Match.Sources, rule.Match.AnySource)
	if !known {
		return nil, nil, Cost{}, ErrUnsafe
	}
	dst, known := policy.Addresses(fw, rule.Match.Destinations, rule.Match.AnyDestination)
	if !known {
		return nil, nil, Cost{}, ErrUnsafe
	}
	terms, known := policy.Services(fw, rule.Match.Services, rule.Match.AnyService)
	if !known {
		return nil, nil, Cost{}, ErrUnsafe
	}
	for _, box := range gap.Boxes() {
		addresses, _ := flow.NewSet(box.Source)
		if !src.Contains(addresses) {
			ref := ensureAddress(&d, box.Source)
			if !slices.Contains(change.Sources, ref) {
				change.Sources = append(change.Sources, ref)
				rule.Match.Sources = append(rule.Match.Sources, ref)
			}
			src = src.Union(addresses)
		}
		addresses, _ = flow.NewSet(box.Destination)
		if !dst.Contains(addresses) {
			ref := ensureAddress(&d, box.Destination)
			if !slices.Contains(change.Destinations, ref) {
				change.Destinations = append(change.Destinations, ref)
				rule.Match.Destinations = append(rule.Match.Destinations, ref)
			}
			dst = dst.Union(addresses)
		}
		term := serviceOf(box)
		if !slices.Contains(terms, term) && !rule.Match.AnyService {
			ref := ensureService(&d, term)
			if !slices.Contains(change.Services, ref) {
				change.Services = append(change.Services, ref)
				rule.Match.Services = append(rule.Match.Services, ref)
				terms = append(terms, term)
			}
		}
	}
	count := len(change.Sources) + len(change.Destinations) + len(change.Services)
	if count == 0 {
		return nil, nil, Cost{}, nil
	}
	for i := range d.Rules {
		if d.Rules[i].ID == rule.ID {
			d.Rules[i] = rule
		}
	}
	next, err := fm.Seal(d)
	cost := Cost{AppendedMembers: count, NewObjects: len(d.Addresses) + len(d.Services) - objects, ModifiedRules: 1, Position: rule.Position, ID: string(rule.ID)}
	return next, []Change{change}, cost, err
}
func createCandidate(fw *fm.Firewall, q policy.Request, gap flow.Traffic) (*fm.Firewall, []Change, Cost, error) {
	d := fw.Export()
	objects := len(d.Addresses) + len(d.Services)
	boxes := gap.Boxes()
	var changes []Change
	var newRules []fm.RuleRecord
	for i, box := range boxes {
		id := generatedID("fm-new-", box)
		for _, r := range d.Rules {
			if r.ID == id {
				id += "-new"
			}
		}
		m := fm.Match{Sources: []fm.AddressRef{ensureAddress(&d, box.Source)}, Destinations: []fm.AddressRef{ensureAddress(&d, box.Destination)}, Services: []fm.ServiceRef{ensureService(&d, serviceOf(box))}}
		if q.FromZone == "" {
			m.AnyFromZone = true
		} else {
			m.FromZones = []fm.ID{q.FromZone}
		}
		if q.ToZone == "" {
			m.AnyToZone = true
		} else {
			m.ToZones = []fm.ID{q.ToZone}
		}
		newRules = append(newRules, fm.RuleRecord{Object: fm.Object{ID: id, Name: string(id), Scope: q.Scope}, RuleSet: q.RuleSet, Position: i, Match: m, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant})
		changes = append(changes, Change{Kind: CreateRule, Rule: id, Sources: m.Sources, Destinations: m.Destinations, Services: m.Services})
	}
	// Preserve prior relative order, including sparse native positions.
	slices.SortStableFunc(d.Rules, func(a, b fm.RuleRecord) int {
		if a.Position < b.Position {
			return -1
		}
		if a.Position > b.Position {
			return 1
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	for i := range d.Rules {
		d.Rules[i].Position = i + len(newRules)
	}
	d.Rules = append(newRules, d.Rules...)
	next, err := fm.Seal(d)
	cost := Cost{NewRules: len(changes), NewObjects: len(d.Addresses) + len(d.Services) - objects}
	return next, changes, cost, err
}
