package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func sameZones(m fm.Match, q policy.Request) bool {
	from := q.FromZone == "" && m.AnyFromZone || !m.AnyFromZone && len(m.FromZones) == 1 && m.FromZones[0] == q.FromZone
	to := q.ToZone == "" && m.AnyToZone || !m.AnyToZone && len(m.ToZones) == 1 && m.ToZones[0] == q.ToZone
	return from && to
}

func generatedID(prefix string, value any) fm.ID {
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return fm.ID(prefix + hex.EncodeToString(sum[:8]))
}

func addressVisible(ctx context.Context, d *fm.Data, a fm.AddressRecord, zones []fm.ID, visits *visitBudget) (bool, error) {
	name := a.Name
	if name == "" {
		name = string(a.ID)
	}
	contexts := zones
	if len(contexts) == 0 {
		if err := visits.take(ctx, len(d.Zones)); err != nil {
			return false, err
		}
		for _, z := range d.Zones {
			contexts = append(contexts, z.ID)
		}
	}
	if len(contexts) == 0 {
		return a.Scope == "", nil
	}
	for _, id := range contexts {
		if err := visits.take(ctx, 1); err != nil {
			return false, err
		}
		scope, found := "", false
		for _, z := range d.Zones {
			if err := visits.take(ctx, 1); err != nil {
				return false, err
			}
			if z.ID == id {
				scope, found = z.AddressScope, true
				break
			}
		}
		if !found || a.Scope != "" && a.Scope != scope {
			return false, nil
		}
		if a.Scope != "" || scope == "" {
			continue
		}
		// Local objects or groups can shadow a globally available address name.
		for _, other := range d.Addresses {
			if err := visits.take(ctx, 1); err != nil {
				return false, err
			}
			if other.Scope == scope && (other.Name == name || other.Name == "" && string(other.ID) == name) {
				return false, nil
			}
		}
		for _, other := range d.AddressGroups {
			if err := visits.take(ctx, 1); err != nil {
				return false, err
			}
			if other.Scope == scope && (other.Name == name || other.Name == "" && string(other.ID) == name) {
				return false, nil
			}
		}
	}
	return true, nil
}

// objectCatalog indexes one owned candidate draft in declaration order.
// It shares the parent planner's visits across indexing and scoped reuse.
type objectCatalog struct {
	data      *fm.Data
	visits    *visitBudget
	addresses map[flow.AddressRange][]fm.AddressRecord
	services  map[fm.ServiceTerm]fm.ServiceRef
}

func newObjectCatalog(ctx context.Context, data *fm.Data, visits *visitBudget) (*objectCatalog, error) {
	if err := visits.take(ctx, len(data.Addresses)+len(data.Services)); err != nil {
		return nil, err
	}
	c := &objectCatalog{data: data, visits: visits, addresses: make(map[flow.AddressRange][]fm.AddressRecord), services: make(map[fm.ServiceTerm]fm.ServiceRef)}
	for _, a := range data.Addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(a.Ranges) == 1 && a.FQDN == "" && a.VIP == (fm.NATRef{}) && len(a.Unsupported) == 0 {
			c.addresses[a.Ranges[0]] = append(c.addresses[a.Ranges[0]], a)
		}
	}
	for _, s := range data.Services {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if s.Scope == "" && len(s.Terms) == 1 && len(s.Unsupported) == 0 {
			if _, found := c.services[s.Terms[0]]; !found {
				c.services[s.Terms[0]] = fm.ServiceRef{Kind: fm.ServiceObject, ID: s.ID}
			}
		}
	}
	return c, nil
}

func (c *objectCatalog) ensureAddress(ctx context.Context, r flow.AddressRange, zones []fm.ID) (fm.AddressRef, error) {
	d := c.data
	for _, a := range c.addresses[r] {
		if err := c.visits.take(ctx, 1); err != nil {
			return fm.AddressRef{}, err
		}
		visible, err := addressVisible(ctx, d, a, zones, c.visits)
		if err != nil {
			return fm.AddressRef{}, err
		}
		if visible {
			return fm.AddressRef{Kind: fm.AddressObject, ID: a.ID}, nil
		}
	}
	id := generatedID("fm-a-", r)
	for {
		collision, err := c.addressCollision(ctx, id)
		if err != nil {
			return fm.AddressRef{}, err
		}
		if !collision {
			break
		}
		id += "-new"
	}
	a := fm.AddressRecord{Object: fm.Object{ID: id, Name: string(id)}, Ranges: []flow.AddressRange{r}}
	d.Addresses = append(d.Addresses, a)
	c.addresses[r] = append(c.addresses[r], a)
	return fm.AddressRef{Kind: fm.AddressObject, ID: id}, nil
}

func (c *objectCatalog) addressCollision(ctx context.Context, id fm.ID) (bool, error) {
	for _, a := range c.data.Addresses {
		if err := c.visits.take(ctx, 1); err != nil {
			return false, err
		}
		if a.ID == id || a.Name == string(id) {
			return true, nil
		}
	}
	for _, g := range c.data.AddressGroups {
		if err := c.visits.take(ctx, 1); err != nil {
			return false, err
		}
		if g.ID == id || g.Name == string(id) {
			return true, nil
		}
	}
	return false, nil
}

func serviceOf(b flow.TrafficRegion) fm.ServiceTerm {
	return fm.ServiceTerm{Protocol: b.Protocol, SourcePort: b.SourcePort, DestinationPort: b.DestinationPort, ICMPType: b.ICMPType, ICMPCode: b.ICMPCode}
}

func (c *objectCatalog) ensureService(ctx context.Context, term fm.ServiceTerm) (fm.ServiceRef, error) {
	if err := c.visits.take(ctx, 1); err != nil {
		return fm.ServiceRef{}, err
	}
	if ref, found := c.services[term]; found {
		return ref, nil
	}
	id := generatedID("fm-s-", term)
	for _, s := range c.data.Services {
		if err := c.visits.take(ctx, 1); err != nil {
			return fm.ServiceRef{}, err
		}
		if s.ID == id {
			id += "-new"
		}
	}
	c.data.Services = append(c.data.Services, fm.ServiceRecord{Object: fm.Object{ID: id, Name: string(id)}, Terms: []fm.ServiceTerm{term}})
	ref := fm.ServiceRef{Kind: fm.ServiceObject, ID: id}
	c.services[term] = ref
	return ref, nil
}

func (c *objectCatalog) match(ctx context.Context, box flow.TrafficRegion, q policy.Request) (fm.Match, error) {
	m := fm.Match{AnyFromZone: q.FromZone == "", AnyToZone: q.ToZone == ""}
	if !m.AnyFromZone {
		m.FromZones = []fm.ID{q.FromZone}
	}
	if !m.AnyToZone {
		m.ToZones = []fm.ID{q.ToZone}
	}
	source, err := c.ensureAddress(ctx, box.Source, m.FromZones)
	if err != nil {
		return fm.Match{}, err
	}
	destination, err := c.ensureAddress(ctx, box.Destination, m.ToZones)
	if err != nil {
		return fm.Match{}, err
	}
	service, err := c.ensureService(ctx, serviceOf(box))
	if err != nil {
		return fm.Match{}, err
	}
	m.Sources = []fm.AddressRef{source}
	m.Destinations = []fm.AddressRef{destination}
	m.Services = []fm.ServiceRef{service}
	return m, nil
}

func (p Planner) appendCandidate(ctx context.Context, fw *fm.Firewall, rule fm.RuleRecord, gap flow.Traffic, visits *visitBudget) (*fm.Firewall, []Change, Cost, error) {
	if err := visits.take(ctx, fw.RecordCount()); err != nil {
		return nil, nil, Cost{}, err
	}
	d := fw.Export()
	catalog, err := newObjectCatalog(ctx, &d, visits)
	if err != nil {
		return nil, nil, Cost{}, err
	}
	objects := len(d.Addresses) + len(d.Services)
	change := Change{Kind: AppendMembers, Rule: rule.ID}
	src, known, err := p.Engine.ResolveAddresses(ctx, fw, rule.Match.Sources, rule.Match.AnySource)
	if err != nil {
		return nil, nil, Cost{}, err
	}
	if !known {
		return nil, nil, Cost{}, ErrUnsafe
	}
	dst, known, err := p.Engine.ResolveAddresses(ctx, fw, rule.Match.Destinations, rule.Match.AnyDestination)
	if err != nil {
		return nil, nil, Cost{}, err
	}
	if !known {
		return nil, nil, Cost{}, ErrUnsafe
	}
	terms, known, err := p.Engine.ResolveServices(ctx, fw, rule.Match.Services, rule.Match.AnyService)
	if err != nil {
		return nil, nil, Cost{}, err
	}
	if !known {
		return nil, nil, Cost{}, ErrUnsafe
	}
	if err := visits.take(ctx, gap.RegionCount()); err != nil {
		return nil, nil, Cost{}, err
	}
	for _, box := range gap.Regions() {
		if err := ctx.Err(); err != nil {
			return nil, nil, Cost{}, err
		}
		addresses, _ := flow.NewAddressSet(box.Source)
		if !src.Contains(addresses) {
			ref, err := catalog.ensureAddress(ctx, box.Source, rule.Match.FromZones)
			if err != nil {
				return nil, nil, Cost{}, err
			}
			if !slices.Contains(change.Sources, ref) {
				change.Sources = append(change.Sources, ref)
				rule.Match.Sources = append(rule.Match.Sources, ref)
			}
			src = src.Union(addresses)
		}
		addresses, _ = flow.NewAddressSet(box.Destination)
		if !dst.Contains(addresses) {
			ref, err := catalog.ensureAddress(ctx, box.Destination, rule.Match.ToZones)
			if err != nil {
				return nil, nil, Cost{}, err
			}
			if !slices.Contains(change.Destinations, ref) {
				change.Destinations = append(change.Destinations, ref)
				rule.Match.Destinations = append(rule.Match.Destinations, ref)
			}
			dst = dst.Union(addresses)
		}
		term := serviceOf(box)
		if !slices.Contains(terms, term) && !rule.Match.AnyService {
			ref, err := catalog.ensureService(ctx, term)
			if err != nil {
				return nil, nil, Cost{}, err
			}
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
	if err := visits.take(ctx, len(d.Rules)); err != nil {
		return nil, nil, Cost{}, err
	}
	for i := range d.Rules {
		if d.Rules[i].ID == rule.ID {
			d.Rules[i] = rule
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, Cost{}, err
	}
	next, err := fm.Seal(d)
	cost := Cost{AppendedMembers: count, NewObjects: len(d.Addresses) + len(d.Services) - objects, ModifiedRules: 1, Position: rule.Position, ID: string(rule.ID)}
	return next, []Change{change}, cost, err
}

func createCandidate(ctx context.Context, fw *fm.Firewall, q policy.Request, gap flow.Traffic, visits *visitBudget) (*fm.Firewall, []Change, Cost, error) {
	if err := visits.take(ctx, fw.RecordCount()); err != nil {
		return nil, nil, Cost{}, err
	}
	d := fw.Export()
	catalog, err := newObjectCatalog(ctx, &d, visits)
	if err != nil {
		return nil, nil, Cost{}, err
	}
	objects := len(d.Addresses) + len(d.Services)
	if err := visits.take(ctx, gap.RegionCount()); err != nil {
		return nil, nil, Cost{}, err
	}
	boxes := gap.Regions()
	var changes []Change
	var newRules []fm.RuleRecord
	for i, box := range boxes {
		if err := ctx.Err(); err != nil {
			return nil, nil, Cost{}, err
		}
		id := generatedID("fm-new-", box)
		for _, r := range d.Rules {
			if err := visits.take(ctx, 1); err != nil {
				return nil, nil, Cost{}, err
			}
			if r.ID == id {
				id += "-new"
			}
		}
		m, err := catalog.match(ctx, box, q)
		if err != nil {
			return nil, nil, Cost{}, err
		}
		newRules = append(newRules, fm.RuleRecord{Object: fm.Object{ID: id, Name: string(id), Scope: q.Scope}, RuleSet: q.RuleSet, Position: i, Match: m, Action: fm.Permit, Log: fm.Irrelevant, LogStart: fm.Irrelevant, LogEnd: fm.Irrelevant})
		changes = append(changes, Change{Kind: CreateRule, Rule: id, Sources: m.Sources, Destinations: m.Destinations, Services: m.Services})
	}
	if err := visits.take(ctx, len(d.Rules)); err != nil {
		return nil, nil, Cost{}, err
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
	if err := visits.take(ctx, len(d.Rules)); err != nil {
		return nil, nil, Cost{}, err
	}
	for i := range d.Rules {
		d.Rules[i].Position = i + len(newRules)
	}
	d.Rules = append(newRules, d.Rules...)
	if err := ctx.Err(); err != nil {
		return nil, nil, Cost{}, err
	}
	next, err := fm.Seal(d)
	cost := Cost{NewRules: len(changes), NewObjects: len(d.Addresses) + len(d.Services) - objects}
	return next, changes, cost, err
}
