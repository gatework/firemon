package inventory

import (
	"cmp"
	"context"
	"net/netip"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/snapshot"
)

// Candidate is address evidence from a native declaration. Reliable describes
// that declaration only; it never proves business ownership, packet ingress or
// an active policy/NAT match. Scope is the declaration's native namespace.
// Source distinguishes topology catalogs, which have no fm.Kind value.
type Candidate struct {
	Kind      fm.Kind
	ID        fm.ID
	Source    string
	Scope     string
	Zone      fm.ID
	Addresses flow.AddressSet
	View      View
	Reliable  bool
}

// IngressZone is a possible native policy context attached to an interface.
// The caller still needs independent ingress evidence to assert packet arrival.
type IngressZone struct {
	Scope string
	VRF   string
	Zone  fm.ID
}

// Index is an immutable address index for one firewall revision. Ranges retain
// their source identity and coordinate view instead of merging whole catalogs.
type Index struct {
	v4, v6  []indexedRange
	ingress []IngressZone
	cost    int
	limit   int
}

type indexedRange struct {
	addresses flow.AddressRange
	max       netip.Addr
	candidate Candidate
}

type candidateKey struct {
	kind     fm.Kind
	id       fm.ID
	source   string
	scope    string
	zone     fm.ID
	view     View
	reliable bool
}

func keyOf(c Candidate) candidateKey {
	return candidateKey{c.Kind, c.ID, c.Source, c.Scope, c.Zone, c.View, c.Reliable}
}

// Candidates intersects relevant subtrees of a balanced interval index.
// /0 declarations never establish candidate evidence.
// limit bounds input ranges and retained result ranges, including provenance.
func (i *Index) Candidates(ctx context.Context, addresses flow.AddressSet, limit int) ([]Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if i == nil || i.limit == 0 {
		return nil, ErrInvalid
	}
	if limit < 1 || addresses.RangeCount() > limit {
		return nil, flow.ErrBudget
	}
	positions := make(map[candidateKey]int)
	var out []Candidate
	var matches [][]flow.AddressRange
	visits, retained := i.limit, 0
	for _, query := range addresses.Ranges() {
		ranges := i.v6
		if query.First.Is4() {
			ranges = i.v4
		}
		var visit func(int, int) error
		visit = func(lo, hi int) error {
			if lo == hi {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if visits == 0 {
				return flow.ErrBudget
			}
			visits--
			at := lo + (hi-lo)/2
			r := ranges[at]
			if r.max.Compare(query.First) < 0 {
				return nil
			}
			if err := visit(lo, at); err != nil {
				return err
			}
			if r.addresses.First.Compare(query.Last) > 0 {
				return nil
			}
			hit, ok := r.addresses.Intersection(query)
			if !ok {
				return visit(at+1, hi)
			}
			retained++
			if retained > limit {
				return flow.ErrBudget
			}
			key := keyOf(r.candidate)
			position, found := positions[key]
			if !found {
				position = len(out)
				positions[key] = position
				out = append(out, r.candidate)
				matches = append(matches, nil)
			}
			matches[position] = append(matches[position], hit)
			return visit(at+1, hi)
		}
		if err := visit(0, len(ranges)); err != nil {
			return nil, err
		}
	}
	for at := range out {
		out[at].Addresses, _ = flow.NewAddressSet(matches[at]...)
	}
	slices.SortFunc(out, func(a, b Candidate) int {
		return cmp.Or(
			cmp.Compare(a.Source, b.Source), cmp.Compare(a.Scope, b.Scope),
			cmp.Compare(a.ID, b.ID), cmp.Compare(a.Zone, b.Zone),
			cmp.Compare(a.View, b.View), cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(boolOrder(a.Reliable), boolOrder(b.Reliable)),
		)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func boolOrder(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (i *Index) Ingress() []IngressZone {
	if i == nil {
		return nil
	}
	return slices.Clone(i.ingress)
}

type indexBuilder struct {
	index *Index
	left  int
}

func buildIndex(ctx context.Context, fw *fm.Firewall, limit int) (*Index, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fw.DeclarationSize() > limit {
		return nil, snapshot.ErrLimit
	}
	b := indexBuilder{index: &Index{limit: limit}, left: limit}
	for _, build := range []func(context.Context, *fm.Firewall) error{
		b.topology, b.addresses, b.translations, b.ingress,
	} {
		if err := build(ctx, fw); err != nil {
			return nil, err
		}
	}
	for _, ranges := range [][]indexedRange{b.index.v4, b.index.v6} {
		slices.SortFunc(ranges, func(a, b indexedRange) int {
			return cmp.Or(a.addresses.First.Compare(b.addresses.First), a.addresses.Last.Compare(b.addresses.Last))
		})
		if _, err := indexMax(ctx, ranges); err != nil {
			return nil, err
		}
	}
	return b.index, ctx.Err()
}

// The middle element owns each subtree, so balancing needs no node pointers or
// allocations. max lets lookup skip a whole subtree even inside a broad subnet.
func indexMax(ctx context.Context, ranges []indexedRange) (netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	if len(ranges) == 0 {
		return netip.Addr{}, nil
	}
	mid := len(ranges) / 2
	left, err := indexMax(ctx, ranges[:mid])
	if err != nil {
		return netip.Addr{}, err
	}
	right, err := indexMax(ctx, ranges[mid+1:])
	if err != nil {
		return netip.Addr{}, err
	}
	high := ranges[mid].addresses.Last
	if left.Compare(high) > 0 {
		high = left
	}
	if right.Compare(high) > 0 {
		high = right
	}
	ranges[mid].max = high
	return high, nil
}

func (b *indexBuilder) take(ctx context.Context, count int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if count > b.left {
		return snapshot.ErrLimit
	}
	b.left -= count
	return nil
}

func (b *indexBuilder) add(ctx context.Context, candidate Candidate, ranges ...flow.AddressRange) error {
	if err := b.take(ctx, len(ranges)); err != nil {
		return err
	}
	var selected []flow.AddressRange
	for _, r := range ranges {
		if r.Valid() && !unrestricted(r) {
			selected = append(selected, r)
		}
	}
	set, _ := flow.NewAddressSet(selected...)
	for _, r := range set.Ranges() {
		if unrestricted(r) {
			continue
		}
		entry := indexedRange{addresses: r, candidate: candidate}
		if r.First.Is4() {
			b.index.v4 = append(b.index.v4, entry)
		} else {
			b.index.v6 = append(b.index.v6, entry)
		}
		b.index.cost++
	}
	return nil
}

func unrestricted(r flow.AddressRange) bool {
	return r.First.IsUnspecified() && !r.Last.Next().IsValid()
}

func (b *indexBuilder) topology(ctx context.Context, fw *fm.Firewall) error {
	for _, iface := range fw.Interfaces() {
		if err := b.take(ctx, 1); err != nil {
			return err
		}
		if iface.Disabled() {
			continue
		}
		c := Candidate{ID: iface.ID(), Source: "interface", Scope: iface.Scope(), View: Original, Reliable: !iface.HasUnsupported()}
		if zone := iface.Zone(); zone != nil {
			c.Zone = zone.ID()
			c.Reliable = c.Reliable && !zone.HasUnsupported()
		}
		for _, prefix := range iface.Record().Addresses {
			r, err := flow.PrefixRange(prefix)
			if err == nil {
				if err := b.add(ctx, c, r); err != nil {
					return err
				}
			}
		}
	}
	for _, zone := range fw.Zones() {
		if err := b.take(ctx, 1); err != nil {
			return err
		}
		c := Candidate{ID: zone.ID(), Source: "zone", Scope: zone.Scope(), Zone: zone.ID(), View: Original, Reliable: !zone.HasUnsupported()}
		if err := b.add(ctx, c, zone.Record().Networks...); err != nil {
			return err
		}
	}
	for _, route := range fw.Routes() {
		if err := b.take(ctx, 1); err != nil {
			return err
		}
		r := route.Record()
		if r.Destination.Bits() <= 0 {
			continue
		}
		c := Candidate{ID: r.ID, Source: "route", Scope: r.Scope, View: Original, Reliable: !route.HasUnsupported() && len(r.PolicyMatch) == 0}
		if iface := route.Interface(); iface != nil && !iface.Disabled() && iface.Zone() != nil {
			c.Zone = iface.Zone().ID()
			c.Reliable = c.Reliable && !iface.HasUnsupported() && !iface.Zone().HasUnsupported()
		} else {
			c.Reliable = false
		}
		network, err := flow.PrefixRange(r.Destination)
		if err == nil {
			if err := b.add(ctx, c, network); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *indexBuilder) addresses(ctx context.Context, fw *fm.Firewall) error {
	for _, address := range fw.Addresses() {
		if err := b.take(ctx, 1); err != nil {
			return err
		}
		c := Candidate{
			Kind: fm.AddressObject, ID: address.ID(), Source: "address", Scope: address.Scope(), View: Original,
			Reliable: !address.HasUnsupported() && address.FQDN() == "",
		}
		if err := b.add(ctx, c, address.Set().Ranges()...); err != nil {
			return err
		}
	}
	return nil
}

func singleZone(zones []fm.ID, any bool) fm.ID {
	if !any && len(zones) == 1 {
		return zones[0]
	}
	return ""
}

func (b *indexBuilder) mappings(ctx context.Context, candidate Candidate, mappings []fm.Mapping, source bool) error {
	for _, mapping := range mappings {
		c := candidate
		c.Reliable = c.Reliable && mapping.Mode != fm.UnknownMapping
		c.View = Original
		if err := b.add(ctx, c, mapping.Original); err != nil {
			return err
		}
		c.View = Translated
		if err := b.add(ctx, c, mapping.Translated); err != nil {
			return err
		}
		c.View = Real
		real := mapping.Translated
		if source {
			real = mapping.Original
		}
		if err := b.add(ctx, c, real); err != nil {
			return err
		}
	}
	return nil
}

func (b *indexBuilder) translations(ctx context.Context, fw *fm.Firewall) error {
	for _, nat := range fw.StaticNATs() {
		if err := b.take(ctx, 1); err != nil {
			return err
		}
		if nat.Disabled() {
			continue
		}
		r := nat.Record()
		c := Candidate{Kind: fm.StaticNATObject, ID: r.ID, Source: "static-nat", Scope: r.Scope, Reliable: !nat.HasUnsupported() && len(r.Match.Unsupported) == 0}
		c.Zone = singleZone(r.Match.FromZones, r.Match.AnyFromZone)
		if err := b.mappings(ctx, c, r.Source, true); err != nil {
			return err
		}
		c.Zone = singleZone(r.Match.ToZones, r.Match.AnyToZone)
		if err := b.mappings(ctx, c, r.Destination, false); err != nil {
			return err
		}
	}
	for _, nat := range fw.DynamicNATs() {
		if err := b.take(ctx, 1); err != nil {
			return err
		}
		if nat.Disabled() {
			continue
		}
		r := nat.Record()
		c := Candidate{Kind: fm.DynamicNATObject, ID: r.ID, Source: "dynamic-nat", Scope: r.Scope, Reliable: !nat.HasUnsupported() && len(r.Match.Unsupported) == 0}
		c.Zone = singleZone(r.Match.ToZones, r.Match.AnyToZone)
		if err := b.mappings(ctx, c, r.Destination, false); err != nil {
			return err
		}
		for _, pool := range []struct {
			object *fm.NATPool
			mode   fm.TranslationMode
			real   bool
		}{{nat.SourcePool(), r.SourceMode, false}, {nat.DestinationPool(), r.DestinationMode, true}} {
			if pool.object == nil {
				continue
			}
			entry := c
			entry.Reliable = entry.Reliable && !pool.object.HasUnsupported() && pool.mode != fm.UnknownTranslation
			entry.View = Translated
			if err := b.add(ctx, entry, pool.object.Record().Ranges...); err != nil {
				return err
			}
			if pool.real {
				entry.View = Real
				if err := b.add(ctx, entry, pool.object.Record().Ranges...); err != nil {
					return err
				}
			}
		}
		if iface := nat.Interface(); iface != nil && !iface.Disabled() && r.SourceMode == fm.InterfaceIP {
			c.View = Translated
			c.Reliable = c.Reliable && !iface.HasUnsupported()
			if iface.Zone() != nil {
				c.Zone = iface.Zone().ID()
			}
			for _, prefix := range iface.Record().Addresses {
				addr := prefix.Addr()
				if r.InterfaceAddress.IsValid() && r.InterfaceAddress != addr {
					continue
				}
				if err := b.add(ctx, c, flow.AddressRange{First: addr, Last: addr}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (b *indexBuilder) ingress(ctx context.Context, fw *fm.Firewall) error {
	byZone := make(map[fm.ID]map[string]struct{})
	global := make(map[string]struct{})
	add := func(scope string, match fm.Match) error {
		if err := b.take(ctx, 1); err != nil {
			return err
		}
		if match.AnyFromZone {
			global[scope] = struct{}{}
		}
		for _, zone := range match.FromZones {
			if err := b.take(ctx, 1); err != nil {
				return err
			}
			if byZone[zone] == nil {
				byZone[zone] = make(map[string]struct{})
			}
			byZone[zone][scope] = struct{}{}
		}
		return nil
	}
	for rule := range fw.OrderedRules() {
		if err := add(rule.Scope(), rule.Record().Match); err != nil {
			return err
		}
	}
	for _, nat := range fw.StaticNATs() {
		if !nat.Disabled() {
			if err := add(nat.Scope(), nat.Record().Match); err != nil {
				return err
			}
		}
	}
	for _, nat := range fw.DynamicNATs() {
		if !nat.Disabled() {
			if err := add(nat.Scope(), nat.Record().Match); err != nil {
				return err
			}
		}
	}
	seen := make(map[IngressZone]struct{})
	for _, iface := range fw.Interfaces() {
		if err := b.take(ctx, 1); err != nil {
			return err
		}
		if iface.Disabled() || iface.Zone() == nil {
			continue
		}
		zone := iface.Zone().ID()
		appendScope := func(scope string) error {
			if err := b.take(ctx, 1); err != nil {
				return err
			}
			entry := IngressZone{Scope: scope, VRF: iface.Scope(), Zone: zone}
			if _, found := seen[entry]; found {
				return nil
			}
			seen[entry] = struct{}{}
			b.index.ingress = append(b.index.ingress, entry)
			b.index.cost++
			return nil
		}
		for scope := range byZone[zone] {
			if err := appendScope(scope); err != nil {
				return err
			}
		}
		for scope := range global {
			if err := appendScope(scope); err != nil {
				return err
			}
		}
		if len(byZone[zone]) == 0 && len(global) == 0 {
			if err := appendScope(fw.Metadata().Context); err != nil {
				return err
			}
		}
	}
	slices.SortFunc(b.index.ingress, func(a, c IngressZone) int {
		return cmp.Or(cmp.Compare(a.Scope, c.Scope), cmp.Compare(a.VRF, c.VRF), cmp.Compare(a.Zone, c.Zone))
	})
	return nil
}
