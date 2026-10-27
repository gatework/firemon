package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	fm "github.com/gatework/firemon"
	"maps"
	"slices"
	"strings"
	"time"
)

var ErrReadback = errors.New("readback does not establish the approved configuration")

// Readback records a successful independent graph comparison, not permission to
// execute commands. RuleIDs maps planned identities to device-allocated IDs.
type Readback struct {
	PlanDigest, ObservedDigest, SourceDigest string
	ruleIDs                                  map[fm.ID]fm.ID
}

func (r Readback) RuleIDs() map[fm.ID]fm.ID { return maps.Clone(r.ruleIDs) }

// Verify compares every supported declaration with the planned result, retains
// native relative order and reruns the traffic proof on the independently parsed
// graph. It permits allocated IDs only for newly created rules. No graph is
// reconstructed from an approval document or a command success flag.
func (p *Plan) Verify(ctx context.Context, observed *fm.Firewall) (Readback, error) {
	if err := ctx.Err(); err != nil {
		return Readback{}, err
	}
	if p == nil || p.before == nil || p.after == nil || observed == nil || !observed.Complete() {
		return Readback{}, ErrReadback
	}
	expected, actual := p.after.Export(), observed.Export()
	created := make(map[fm.ID]bool)
	for _, change := range p.changes {
		if change.Kind == CreateRule {
			created[change.Rule] = true
		}
	}
	ids := make(map[fm.ID]fm.ID)
	// Build the unmatched native declarations once; do not scan every rule for
	// every creation. A signature collision/ambiguity is not resolved by guessing.
	type native struct {
		index int
		id    fm.ID
	}
	available := make(map[string][]native)
	for i, rule := range actual.Rules {
		if p.before.Rule(rule.ID) != nil {
			continue
		}
		key, err := ruleSignature(rule)
		if err != nil {
			return Readback{}, err
		}
		available[key] = append(available[key], native{i, rule.ID})
	}
	for _, rule := range expected.Rules {
		if err := ctx.Err(); err != nil {
			return Readback{}, err
		}
		if !created[rule.ID] {
			continue
		}
		key, err := ruleSignature(rule)
		if err != nil {
			return Readback{}, err
		}
		matches := available[key]
		if len(matches) != 1 {
			return Readback{}, fmt.Errorf("%w: new rule %s is missing or ambiguous", ErrReadback, rule.ID)
		}
		candidate := matches[0]
		ids[rule.ID] = candidate.id
		actual.Rules[candidate.index].ID = rule.ID
		delete(available, key)
	}
	if len(available) > 0 {
		return Readback{}, fmt.Errorf("%w: unexpected native rules", ErrReadback)
	}
	before, err := normalized(p.before.Export())
	if err != nil {
		return Readback{}, err
	}
	want, err := normalized(expected)
	if err != nil {
		return Readback{}, err
	}
	got, err := normalized(actual)
	if err != nil {
		return Readback{}, err
	}
	if want.SemanticDigest() != got.SemanticDigest() {
		return Readback{}, ErrReadback
	}
	if p.preservation != nil {
		_, err = p.engine.Equivalent(ctx, before, got, p.preservation.From)
	} else if len(p.transfers) > 0 {
		_, err = (Planner{Engine: p.engine}).proveTransfers(ctx, before, got, p.changes, p.transferFrom)
	} else {
		_, err = (Planner{Engine: p.engine}).prove(ctx, before, got, p.target)
	}
	if err != nil {
		return Readback{}, fmt.Errorf("%w: traffic proof: %w", ErrReadback, err)
	}
	return Readback{PlanDigest: p.digest, ObservedDigest: observed.SemanticDigest(), SourceDigest: observed.Metadata().SourceDigest, ruleIDs: ids}, nil
}

// VerifyBaseline checks a fresh capture before any write, allowing only
// serialization differences in line positions and member ordering.
func (p *Plan) VerifyBaseline(ctx context.Context, observed *fm.Firewall) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil || p.before == nil || observed == nil || !observed.Complete() {
		return ErrReadback
	}
	a, err := normalized(p.before.Export())
	if err != nil {
		return err
	}
	b, err := normalized(observed.Export())
	if err != nil {
		return err
	}
	if a.SemanticDigest() != b.SemanticDigest() {
		return ErrReadback
	}
	return ctx.Err()
}

func ruleSignature(r fm.RuleRecord) (string, error) {
	r.ID, r.Name, r.Spans, r.Position = "", "", nil, 0
	normalizeMatch(&r.Match)
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeMatch(m *fm.Match) {
	slices.SortFunc(m.Sources, compareAddressRef)
	slices.SortFunc(m.Destinations, compareAddressRef)
	slices.SortFunc(m.Services, func(a, b fm.ServiceRef) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	slices.Sort(m.FromZones)
	slices.Sort(m.ToZones)
	slices.Sort(m.Applications)
	slices.Sort(m.Users)
}
func compareAddressRef(a, b fm.AddressRef) int {
	if a.Kind != b.Kind {
		return int(a.Kind) - int(b.Kind)
	}
	return strings.Compare(string(a.ID), string(b.ID))
}

// normalized uses semantic graph validation again; it removes evidence layout,
// never semantic fields, catalog identity, software version or parser version.
func normalized(d fm.Data) (*fm.Firewall, error) {
	d.Raw, d.Evidence, d.Diagnostics = "", nil, nil
	d.Metadata.SourceDigest, d.Metadata.CapturedAt = "", time.Time{}
	slices.SortStableFunc(d.Rules, func(a, b fm.RuleRecord) int {
		if c := strings.Compare(a.Scope, b.Scope); c != 0 {
			return c
		}
		if c := strings.Compare(a.RuleSet, b.RuleSet); c != 0 {
			return c
		}
		if a.Position < b.Position {
			return -1
		}
		if a.Position > b.Position {
			return 1
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	positions := make(map[[4]string]int)
	for i := range d.Rules {
		r := &d.Rules[i]
		key := [4]string{r.Scope, r.RuleSet}
		// Junos and ScreenOS order ordinary policies within each zone pair.
		// Reordering independent pair blocks does not reorder either chain.
		if (d.Metadata.Vendor == "srx" && !r.Builtin || d.Metadata.Vendor == "netscreen") && len(r.Match.FromZones) == 1 && len(r.Match.ToZones) == 1 && !r.Match.AnyFromZone && !r.Match.AnyToZone {
			key[2], key[3] = string(r.Match.FromZones[0]), string(r.Match.ToZones[0])
		}
		r.Position = positions[key]
		positions[key]++
		if (d.Metadata.Vendor == "srx" || d.Metadata.Vendor == "netscreen") && r.Builtin && r.Match.AnyFromZone && r.Match.AnyToZone {
			r.Position = len(d.Rules) // The global implicit default remains terminal.
		}
		r.Name = "" // Rule ID carries native identity; Name is its display label.
		normalizeMatch(&r.Match)
	}
	// Keep the native NAT stage/section and relative order. Line offsets in the
	// source file are not a native position and can change after unrelated edits.
	type natPosition struct {
		scope, section string
		stage          int
	}
	type position struct {
		static      bool
		index, rank int
		id          fm.ID
		key         natPosition
	}
	var order []position
	for i, n := range d.StaticNATs {
		order = append(order, position{true, i, n.Order.Position, n.ID, natPosition{n.Scope, n.Order.Section, n.Order.Stage}})
	}
	for i, n := range d.DynamicNATs {
		order = append(order, position{false, i, n.Order.Position, n.ID, natPosition{n.Scope, n.Order.Section, n.Order.Stage}})
	}
	slices.SortStableFunc(order, func(a, b position) int {
		if a.rank < b.rank {
			return -1
		}
		if a.rank > b.rank {
			return 1
		}
		return strings.Compare(string(a.id), string(b.id))
	})
	next := make(map[natPosition]int)
	for _, p := range order {
		if p.static {
			d.StaticNATs[p.index].Order.Position = next[p.key]
			normalizeMatch(&d.StaticNATs[p.index].Match)
		} else {
			d.DynamicNATs[p.index].Order.Position = next[p.key]
			normalizeMatch(&d.DynamicNATs[p.index].Match)
		}
		next[p.key]++
	}
	return fm.Seal(d)
}
