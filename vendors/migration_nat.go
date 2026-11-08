package vendors

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/internal/render"
)

// MigrationCompiler translates selected declarations into native target forms.
// It does not authorize a change. The planner independently proves source
// behavior, packet relations and preservation outside the selected domains.
type MigrationCompiler struct{}

var _ plan.MigrationNATCompiler = MigrationCompiler{}

type natCompilation struct {
	ctx            context.Context
	source, before *fm.Firewall
	draft          plan.NativeMigrationDraft
	changes        plan.NativeChanges
	resolver       *policy.Resolver
	vendor         string
	remaining      int
	positions      map[string]int
	addresses      map[fm.ID]fm.AddressRecord
	services       map[fm.ID]fm.ServiceRecord
}

func natFailure(id fm.ID, code, reason string) error {
	return &plan.MigrationError{Issue: plan.MigrationIssue{Object: id, Code: code, Reason: reason}}
}

func (MigrationCompiler) CompileMigrationNAT(ctx context.Context, source, before *fm.Firewall, draft plan.NativeMigrationDraft) (plan.NativeChanges, error) {
	if err := ctx.Err(); err != nil {
		return plan.NativeChanges{}, err
	}
	if source == nil || before == nil || !source.Complete() || !before.Complete() {
		return plan.NativeChanges{}, plan.ErrInvalid
	}
	limits := draft.Limits.WithDefaults()
	if err := plan.PreflightNativeRequests(ctx, []plan.NativeRequest{{Additions: draft.Changes.Additions}}, limits); err != nil {
		return plan.NativeChanges{}, err
	}
	resolver, err := policy.NewResolver(source, limits)
	if err != nil {
		return plan.NativeChanges{}, err
	}
	c := &natCompilation{ctx: ctx, source: source, before: before, draft: draft, resolver: resolver,
		vendor: before.Metadata().Vendor, remaining: limits.MaxVisits, positions: make(map[string]int),
		addresses: make(map[fm.ID]fm.AddressRecord), services: make(map[fm.ID]fm.ServiceRecord)}
	if err := c.take(source.DeclarationSize(), before.DeclarationSize(), len(draft.Input.Contexts), len(draft.Input.StaticNATs), len(draft.Input.DynamicNATs), len(draft.Input.Interfaces), len(draft.Input.VRFs), len(draft.Rules), len(draft.Changes.Rules)); err != nil {
		return plan.NativeChanges{}, err
	}
	for _, r := range draft.Rules {
		if err := c.take(len(r.Targets)); err != nil {
			return plan.NativeChanges{}, err
		}
	}
	for _, change := range draft.Changes.Rules {
		if err := c.take(len(change.Sources), len(change.Destinations), len(change.Services)); err != nil {
			return plan.NativeChanges{}, err
		}
	}
	if len(draft.Input.Contexts) == 0 || len(draft.Changes.Additions.StaticNATs)+len(draft.Changes.Additions.DynamicNATs)+len(draft.Changes.Additions.NATPools) != 0 {
		return plan.NativeChanges{}, plan.ErrInvalid
	}
	// Clone additions only after preflight; no mutation can escape on refusal.
	c.changes = plan.NativeChanges{Rules: slices.Clone(draft.Changes.Rules),
		Additions: (plan.NativeRequest{Additions: draft.Changes.Additions}).Clone().Additions}
	for i := range c.changes.Rules {
		r := &c.changes.Rules[i]
		r.Sources, r.Destinations, r.Services = slices.Clone(r.Sources), slices.Clone(r.Destinations), slices.Clone(r.Services)
	}
	// All new declarations are candidate data. Source spans belong exclusively
	// to the separately bound source snapshot, never to the target capture.
	for i := range c.changes.Additions.Rules {
		c.changes.Additions.Rules[i].Spans = nil
	}
	for i := range c.changes.Additions.Addresses {
		c.changes.Additions.Addresses[i].Spans = nil
	}
	for i := range c.changes.Additions.Services {
		c.changes.Additions.Services[i].Spans = nil
	}
	for i := range c.changes.Additions.Schedules {
		c.changes.Additions.Schedules[i].Spans = nil
	}
	if draft.Changes.Clock != nil {
		clock := *draft.Changes.Clock
		c.changes.Clock = &clock
	}
	for _, a := range c.changes.Additions.Addresses {
		c.addresses[a.ID] = a
	}
	for _, s := range c.changes.Additions.Services {
		c.services[s.ID] = s
	}
	for _, entry := range before.NATSequence() {
		key := fmt.Sprintf("%d:%s", entry.Order.Stage, entry.Order.Section)
		c.positions[key] = max(c.positions[key], entry.Order.Position+1)
	}
	selected := make(map[fm.NATRef]bool)
	for _, id := range draft.Input.StaticNATs {
		key := fm.NATRef{Kind: fm.StaticNATObject, ID: id}
		if selected[key] || source.StaticNAT(id) == nil {
			return plan.NativeChanges{}, plan.ErrInvalid
		}
		selected[key] = true
	}
	for _, id := range draft.Input.DynamicNATs {
		key := fm.NATRef{Kind: fm.DynamicNATObject, ID: id}
		if selected[key] || source.DynamicNAT(id) == nil {
			return plan.NativeChanges{}, plan.ErrInvalid
		}
		selected[key] = true
	}
	for _, entry := range source.NATSequence() {
		if err := c.take(1); err != nil {
			return plan.NativeChanges{}, err
		}
		if !selected[fm.NATRef{Kind: entry.Kind, ID: entry.ID}] {
			continue
		}
		if entry.Kind == fm.StaticNATObject {
			err = c.compileStatic(source.StaticNAT(entry.ID).Record())
		} else {
			err = c.compileDynamic(source.DynamicNAT(entry.ID).Record())
		}
		if err != nil {
			return plan.NativeChanges{}, err
		}
	}
	if len(selected) != 0 && len(c.changes.Additions.StaticNATs)+len(c.changes.Additions.DynamicNATs) == 0 {
		return plan.NativeChanges{}, natFailure("", "nat-context", "selected translation has no mapped native context")
	}
	if err := plan.PreflightNativeRequests(ctx, []plan.NativeRequest{{Additions: c.changes.Additions}}, limits); err != nil {
		return plan.NativeChanges{}, err
	}
	// Native renderers remain the authority for release gates, names, object
	// ownership and grammar. A failed target form never returns a partial delta.
	if err := c.checkNative(); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, policy.ErrBudget) {
			return plan.NativeChanges{}, err
		}
		return plan.NativeChanges{}, natFailure("", "native-nat-form", "target release cannot emit the selected translation and dependencies")
	}
	return c.changes, nil
}

func (c *natCompilation) take(counts ...int) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	for _, count := range counts {
		if count < 0 || count > c.remaining {
			return policy.ErrBudget
		}
		c.remaining -= count
	}
	return nil
}

func (c *natCompilation) resolveAddresses(refs []fm.AddressRef, any bool) (flow.AddressSet, bool, error) {
	if err := c.take(0); err != nil {
		return flow.AddressSet{}, false, err
	}
	if err := c.resolver.RestrictVisits(c.remaining); err != nil {
		return flow.AddressSet{}, false, err
	}
	visits := c.resolver.Visits()
	set, known, err := c.resolver.Addresses(c.ctx, refs, any)
	c.remaining -= c.resolver.Visits() - visits
	return set, known, err
}

func (c *natCompilation) resolveServices(refs []fm.ServiceRef, any bool) ([]fm.ServiceTerm, bool, error) {
	if err := c.take(0); err != nil {
		return nil, false, err
	}
	if err := c.resolver.RestrictVisits(c.remaining); err != nil {
		return nil, false, err
	}
	visits := c.resolver.Visits()
	terms, known, err := c.resolver.Services(c.ctx, refs, any)
	c.remaining -= c.resolver.Visits() - visits
	return terms, known, err
}

func (c *natCompilation) checkNative() error {
	if err := c.take(c.before.DeclarationSize()); err != nil {
		return err
	}
	d := c.before.Export()
	a := c.changes.Additions
	old := make([]fm.RuleRecord, 0, c.before.RuleCount())
	for rule := range c.before.OrderedRules() {
		r := rule.Record()
		r.Position = len(a.Rules) + len(old)
		old = append(old, r)
	}
	d.Rules = append(slices.Clone(a.Rules), old...)
	d.Addresses = append(d.Addresses, a.Addresses...)
	d.Services = append(d.Services, a.Services...)
	d.Schedules = append(d.Schedules, a.Schedules...)
	d.StaticNATs = append(d.StaticNATs, a.StaticNATs...)
	d.DynamicNATs = append(d.DynamicNATs, a.DynamicNATs...)
	d.NATPools = append(d.NATPools, a.NATPools...)
	after, err := fm.Seal(d)
	if err != nil {
		return err
	}
	driver, err := lookup(c.vendor)
	if err != nil {
		return err
	}
	_, err = driver.renderer.RenderNative(c.ctx, c.before, after, c.changes)
	return err
}

func natName(id fm.ID, target plan.MigrationContext, direction string) string {
	// This fixed DTO has only strings and cannot fail JSON encoding. Field
	// boundaries are retained even when native names contain punctuation.
	encoded, _ := json.Marshal(struct {
		Source    fm.ID
		Target    plan.MigrationContext
		Direction string
	}{id, target, direction})
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("fm-nat-%x", sum[:6])
}

func natIdentity(kind string, parts ...string) fm.ID {
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return fm.ID(kind + ":" + strings.Join(parts, "/"))
}

func (c *natCompilation) order(stage int, section string) fm.NATOrder {
	key := fmt.Sprintf("%d:%s", stage, section)
	position := c.positions[key]
	c.positions[key] = position + 1
	return fm.NATOrder{Stage: stage, Section: section, Position: position}
}

func (c *natCompilation) contexts(o fm.Object, m fm.Match) ([]plan.MigrationContextMapping, error) {
	if len(o.Unsupported) != 0 || !render.PlainMatch(m) {
		return nil, natFailure(o.ID, "unknown-nat", "translation has unresolved or unsupported match conditions")
	}
	var out []plan.MigrationContextMapping
	seen := make(map[plan.MigrationContext]bool)
	for _, pair := range c.draft.Input.Contexts {
		if err := c.take(1); err != nil {
			return nil, err
		}
		if o.Scope != pair.Source.Chain.Scope {
			continue
		}
		if !m.AnyFromZone && !slices.Contains(m.FromZones, pair.Source.FromZone) || !m.AnyToZone && !slices.Contains(m.ToZones, pair.Source.ToZone) {
			continue
		}
		if pair.Target.FromZone == "" || pair.Target.ToZone == "" || c.before.Zone(pair.Target.FromZone) == nil || c.before.Zone(pair.Target.ToZone) == nil {
			return nil, natFailure(o.ID, "nat-zone-mapping", "translation requires explicit existing target ingress and egress zones")
		}
		if seen[pair.Target] {
			continue
		}
		seen[pair.Target] = true
		out = append(out, pair)
	}
	if len(out) == 0 {
		return nil, natFailure(o.ID, "nat-context", "translation does not belong to a mapped source context")
	}
	return out, nil
}

func (c *natCompilation) iface(source fm.ID) (fm.ID, error) {
	if source == "" {
		return "", nil
	}
	for _, pair := range c.draft.Input.Interfaces {
		if err := c.take(1); err != nil {
			return "", err
		}
		if pair.Source == source {
			i := c.before.Interface(pair.Target)
			if i != nil && !i.Disabled() && !i.HasUnsupported() {
				return pair.Target, nil
			}
		}
	}
	return "", natFailure(source, "nat-interface-mapping", "translation requires an explicit supported target interface")
}

func (c *natCompilation) match(source fm.Match, id fm.ID, target plan.MigrationContext) (fm.Match, error) {
	m := fm.Match{AnySource: source.AnySource, AnyDestination: source.AnyDestination, AnyService: source.AnyService,
		FromZones: []fm.ID{target.FromZone}, ToZones: []fm.ID{target.ToZone}}
	for axis, side := range []struct {
		any  bool
		refs []fm.AddressRef
		out  *[]fm.AddressRef
	}{{source.AnySource, source.Sources, &m.Sources}, {source.AnyDestination, source.Destinations, &m.Destinations}} {
		if side.any {
			if len(side.refs) != 0 {
				return fm.Match{}, plan.ErrInvalid
			}
			continue
		}
		set, known, err := c.resolveAddresses(side.refs, false)
		if err != nil {
			return fm.Match{}, err
		}
		if !known || set.Empty() {
			return fm.Match{}, natFailure(id, "unknown-nat-address", "translation match cannot be resolved exactly")
		}
		for index, r := range set.Ranges() {
			if err := c.take(1); err != nil {
				return fm.Match{}, err
			}
			a := fm.AddressRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("%s-a%d-%d", strings.ReplaceAll(string(id), ":", "-"), axis, index))}, Ranges: []flow.AddressRange{r}}
			a.Name = string(a.ID)
			switch c.vendor {
			case "srx":
				if _, err := render.Prefix(r); err != nil {
					return fm.Match{}, natFailure(id, "nat-address-prefix", "SRX native NAT match requires exact prefixes")
				}
				a.Object = fm.Object{ID: natIdentity("nat-address", string(id), string(rune('s'+axis)), r.First.String(), r.Last.String()), Scope: "nat:" + string(id)}
			case "huawei":
				a.Object = fm.Object{ID: fm.ID("$address:" + r.First.String() + "-" + r.Last.String()), Scope: "literal", Inline: true}
				a.Name = string(a.ID)
			}
			if err := c.address(a); err != nil {
				return fm.Match{}, err
			}
			*side.out = append(*side.out, fm.AddressRef{Kind: fm.AddressObject, ID: a.ID})
		}
	}
	if !source.AnyService {
		terms, known, err := c.resolveServices(source.Services, false)
		if err != nil {
			return fm.Match{}, err
		}
		if !known || len(terms) == 0 {
			return fm.Match{}, natFailure(id, "unknown-nat-service", "translation service cannot be resolved exactly")
		}
		if err := c.take(len(terms)); err != nil {
			return fm.Match{}, err
		}
		s := fm.ServiceRecord{Object: fm.Object{ID: fm.ID(strings.ReplaceAll(string(id), ":", "-") + "-svc")}, Terms: terms}
		s.Name = string(s.ID)
		switch c.vendor {
		case "srx":
			if len(terms) != 1 {
				return fm.Match{}, natFailure(id, "nat-service-union", "SRX NAT match requires one service rectangle")
			}
			s.Object = fm.Object{ID: natIdentity("nat-service", string(id)), Scope: "nat:" + string(id)}
		case "huawei":
			var key strings.Builder
			key.WriteString("$service:")
			for _, t := range terms {
				fmt.Fprintf(&key, "%d/%d-%d:%d-%d;", t.Protocol.Low, t.SourcePort.Low, t.SourcePort.High, t.DestinationPort.Low, t.DestinationPort.High)
			}
			s.Object = fm.Object{ID: fm.ID(key.String()), Name: key.String(), Scope: "literal", Inline: true}
		}
		if err := c.service(s); err != nil {
			return fm.Match{}, err
		}
		m.Services = []fm.ServiceRef{{Kind: fm.ServiceObject, ID: s.ID}}
	} else if len(source.Services) != 0 {
		return fm.Match{}, plan.ErrInvalid
	}
	return m, nil
}

func (c *natCompilation) address(a fm.AddressRecord) error {
	if old := c.before.Address(a.ID); old != nil {
		v := old.Record()
		if v.Name != a.Name || v.Scope != a.Scope || v.Inline != a.Inline || v.FQDN != "" || v.VIP != (fm.NATRef{}) || len(v.Unsupported) != 0 || !slices.Equal(v.Ranges, a.Ranges) {
			return natFailure(a.ID, "nat-object-collision", "target address identity has different content")
		}
		return nil
	}
	if old, ok := c.addresses[a.ID]; ok {
		if old.Name != a.Name || old.Scope != a.Scope || old.Inline != a.Inline || old.FQDN != "" || old.VIP != (fm.NATRef{}) || len(old.Unsupported) != 0 || !slices.Equal(old.Ranges, a.Ranges) {
			return natFailure(a.ID, "nat-object-collision", "new address identity has different content")
		}
		return nil
	}
	c.addresses[a.ID] = a
	c.changes.Additions.Addresses = append(c.changes.Additions.Addresses, a)
	return nil
}

func (c *natCompilation) service(s fm.ServiceRecord) error {
	if old := c.before.Service(s.ID); old != nil {
		v := old.Record()
		if v.Name != s.Name || v.Scope != s.Scope || v.Inline != s.Inline || len(v.Unsupported) != 0 || !slices.Equal(v.Terms, s.Terms) {
			return natFailure(s.ID, "nat-object-collision", "target service identity has different content")
		}
		return nil
	}
	if old, ok := c.services[s.ID]; ok {
		if old.Name != s.Name || old.Scope != s.Scope || old.Inline != s.Inline || len(old.Unsupported) != 0 || !slices.Equal(old.Terms, s.Terms) {
			return natFailure(s.ID, "nat-object-collision", "new service identity has different content")
		}
		return nil
	}
	c.services[s.ID] = s
	c.changes.Additions.Services = append(c.changes.Additions.Services, s)
	return nil
}
