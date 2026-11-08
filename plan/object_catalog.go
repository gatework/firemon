package plan

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/internal/nativename"
	"github.com/gatework/firemon/internal/servicecoverage"
	"github.com/gatework/firemon/policy"
)

type catalogReference struct {
	kind fm.Kind
	id   fm.ID
}
type catalogService struct {
	reference catalogReference
	traffic   flow.Traffic
}

// objectCatalog indexes exact resolved coverage in one owned draft. A native
// name must still resolve to that same object in every requested scope.
type objectCatalog struct {
	data                       *fm.Data
	baseline                   *fm.Firewall
	visits                     *visitBudget
	limits                     policy.Limits
	names                      *nameAllocator
	addresses                  map[flow.AddressRange][]catalogReference
	services                   map[fm.ServiceTerm][]catalogService
	addressNames, serviceNames map[nativename.ObjectKey]catalogReference
	zones                      map[fm.ID]string
	addressScopes              []string
}

func newObjectCatalog(ctx context.Context, baseline *fm.Firewall, data *fm.Data, limits policy.Limits, visits *visitBudget) (*objectCatalog, error) {
	if err := visits.nativeCounts(ctx, len(data.Addresses), len(data.AddressGroups), len(data.Services), len(data.ServiceGroups), len(data.Zones)); err != nil {
		return nil, err
	}
	names, err := newNameAllocator(ctx, data, visits)
	if err != nil {
		return nil, err
	}
	limits = limits.WithDefaults()
	resolutionLimits := limits
	resolutionLimits.MaxVisits = max(1, int(*visits))
	resolver, err := policy.NewResolver(baseline, resolutionLimits)
	if err != nil {
		return nil, err
	}
	c := &objectCatalog{data: data, baseline: baseline, visits: visits, limits: limits, names: names, addresses: make(map[flow.AddressRange][]catalogReference, len(data.Addresses)+len(data.AddressGroups)), services: make(map[fm.ServiceTerm][]catalogService, len(data.Services)+len(data.ServiceGroups)), addressNames: make(map[nativename.ObjectKey]catalogReference, len(data.Addresses)+len(data.AddressGroups)), serviceNames: make(map[nativename.ObjectKey]catalogReference, len(data.Services)+len(data.ServiceGroups)), zones: make(map[fm.ID]string)}
	for _, z := range data.Zones {
		c.zones[z.ID] = z.AddressScope
		c.addressScopes = append(c.addressScopes, z.AddressScope)
	}
	indexAddress := func(object fm.Object, kind fm.Kind) error {
		entry := catalogReference{kind: kind, id: object.ID}
		c.recordName(c.addressNames, entry, object)
		if err := resolver.RestrictVisits(int(*visits)); err != nil {
			return err
		}
		spent := resolver.Visits()
		set, known, err := resolver.Addresses(ctx, []fm.AddressRef{{Kind: kind, ID: object.ID}}, false)
		if chargeErr := visits.take(ctx, resolver.Visits()-spent); chargeErr != nil {
			return chargeErr
		}
		if err != nil {
			return err
		}
		if known {
			ranges := set.Ranges()
			if len(ranges) == 1 {
				c.addresses[ranges[0]] = append(c.addresses[ranges[0]], entry)
			}
		}
		return nil
	}
	for _, a := range data.Addresses {
		if err := visits.take(ctx, len(a.Ranges)); err != nil {
			return nil, err
		}
		entry := catalogReference{kind: fm.AddressObject, id: a.ID}
		c.recordName(c.addressNames, entry, a.Object)
		if a.FQDN != "" || a.VIP != (fm.NATRef{}) || len(a.Unsupported) != 0 {
			continue
		}
		ranges := a.Ranges
		if len(ranges) > 1 {
			ranges = baseline.Address(a.ID).Set().Ranges()
		}
		if len(ranges) == 1 {
			c.addresses[ranges[0]] = append(c.addresses[ranges[0]], entry)
		}
	}
	for _, g := range data.AddressGroups {
		if err := indexAddress(g.Object, fm.AddressGroupObject); err != nil {
			return nil, err
		}
	}
	indexService := func(object fm.Object, kind fm.Kind) error {
		entry := catalogReference{kind: kind, id: object.ID}
		c.recordName(c.serviceNames, entry, object)
		if err := resolver.RestrictVisits(int(*visits)); err != nil {
			return err
		}
		spent := resolver.Visits()
		terms, known, err := resolver.Services(ctx, []fm.ServiceRef{{Kind: kind, ID: object.ID}}, false)
		if chargeErr := visits.take(ctx, resolver.Visits()-spent); chargeErr != nil {
			return chargeErr
		}
		if err != nil {
			return err
		}
		if !known || len(terms) == 0 {
			return nil
		}
		if err := visits.take(ctx, len(terms)); err != nil {
			return err
		}
		coverage, err := servicecoverage.FromTerms(ctx, terms, limits.MaxRegions)
		if err != nil {
			return err
		}
		bounds := serviceBounds(terms)
		c.services[bounds] = append(c.services[bounds], catalogService{reference: entry, traffic: coverage})
		return nil
	}
	for _, s := range data.Services {
		if len(s.Terms) == 1 && len(s.Unsupported) == 0 {
			entry := catalogReference{kind: fm.ServiceObject, id: s.ID}
			c.recordName(c.serviceNames, entry, s.Object)
			c.services[s.Terms[0]] = append(c.services[s.Terms[0]], catalogService{reference: entry})
		} else if err := indexService(s.Object, fm.ServiceObject); err != nil {
			return nil, err
		}
	}
	for _, g := range data.ServiceGroups {
		if err := indexService(g.Object, fm.ServiceGroupObject); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *objectCatalog) recordName(index map[nativename.ObjectKey]catalogReference, entry catalogReference, object fm.Object) {
	key := nativename.Object(c.data.Metadata, object, entry.kind == fm.AddressGroupObject || entry.kind == fm.ServiceGroupObject)
	if prior, found := index[key]; found && prior != entry {
		index[key] = catalogReference{}
	} else {
		index[key] = entry
	}
}

// Recover only native identity, without cloning full address/service records.
func (c *objectCatalog) nativeObject(entry catalogReference) fm.Object {
	object := fm.Object{ID: entry.id, Name: string(entry.id)}
	switch entry.kind {
	case fm.AddressObject:
		if v := c.baseline.Address(entry.id); v != nil {
			object.Name, object.Scope = v.Name(), v.Scope()
		}
	case fm.AddressGroupObject:
		if v := c.baseline.AddressGroup(entry.id); v != nil {
			object.Name, object.Scope = v.Name(), v.Scope()
		}
	case fm.ServiceObject:
		if v := c.baseline.Service(entry.id); v != nil {
			object.Name, object.Scope = v.Name(), v.Scope()
		}
	case fm.ServiceGroupObject:
		if v := c.baseline.ServiceGroup(entry.id); v != nil {
			object.Name, object.Scope = v.Name(), v.Scope()
		}
	}
	return object
}
func (c *objectCatalog) visible(entry catalogReference, scope string, index map[nativename.ObjectKey]catalogReference) bool {
	object := c.nativeObject(entry)
	group := entry.kind == fm.AddressGroupObject || entry.kind == fm.ServiceGroupObject
	for _, namespace := range []string{scope, ""} {
		key := nativename.Object(c.data.Metadata, fm.Object{Name: nativename.Name(object), Scope: namespace}, group)
		if found, exists := index[key]; exists {
			return found == entry
		}
	}
	return false
}
func (c *objectCatalog) addressVisible(ctx context.Context, entry catalogReference, zones []fm.ID, scope string) (bool, error) {
	if len(zones) == 0 {
		if len(c.zones) == 0 {
			return c.visible(entry, scope, c.addressNames), ctx.Err()
		}
		for _, book := range c.addressScopes {
			if err := c.visits.take(ctx, 1); err != nil {
				return false, err
			}
			if book == "" {
				book = scope
			}
			if !c.visible(entry, book, c.addressNames) {
				return false, nil
			}
		}
		return true, nil
	}
	for _, zone := range zones {
		if err := c.visits.take(ctx, 1); err != nil {
			return false, err
		}
		book, found := c.zones[zone]
		if !found {
			return false, nil
		}
		if book == "" {
			book = scope
		}
		if !c.visible(entry, book, c.addressNames) {
			return false, nil
		}
	}
	return true, nil
}
func (c *objectCatalog) ensureAddress(ctx context.Context, r flow.AddressRange, zones []fm.ID, scope string) (fm.AddressRef, error) {
	for _, entry := range c.addresses[r] {
		if err := c.visits.take(ctx, 1); err != nil {
			return fm.AddressRef{}, err
		}
		visible, err := c.addressVisible(ctx, entry, zones, scope)
		if err != nil {
			return fm.AddressRef{}, err
		}
		if visible {
			return fm.AddressRef{Kind: entry.kind, ID: entry.id}, nil
		}
	}
	id, err := c.names.object(ctx, generatedID("fm-a-", r), c.names.addresses)
	if err != nil {
		return fm.AddressRef{}, err
	}
	object := fm.Object{ID: id, Name: string(id)}
	c.data.Addresses = append(c.data.Addresses, fm.AddressRecord{Object: object, Ranges: []flow.AddressRange{r}})
	entry := catalogReference{kind: fm.AddressObject, id: object.ID}
	c.addresses[r] = append(c.addresses[r], entry)
	c.recordName(c.addressNames, entry, object)
	return fm.AddressRef{Kind: fm.AddressObject, ID: id}, nil
}
func serviceTermFromRegion(b flow.TrafficRegion) fm.ServiceTerm {
	return fm.ServiceTerm{Protocol: b.Protocol, SourcePort: b.SourcePort, DestinationPort: b.DestinationPort, ICMPType: b.ICMPType, ICMPCode: b.ICMPCode}
}
func serviceIntervals(t *fm.ServiceTerm) [5]*flow.Interval {
	return [5]*flow.Interval{&t.Protocol, &t.SourcePort, &t.DestinationPort, &t.ICMPType, &t.ICMPCode}
}
func serviceBounds(terms []fm.ServiceTerm) fm.ServiceTerm {
	out := terms[0]
	bounds := serviceIntervals(&out)
	for _, term := range terms[1:] {
		for n, interval := range serviceIntervals(&term) {
			bounds[n].Low = min(bounds[n].Low, interval.Low)
			bounds[n].High = max(bounds[n].High, interval.High)
		}
	}
	return out
}
func (c *objectCatalog) ensureService(ctx context.Context, term fm.ServiceTerm, scope string) (fm.ServiceRef, error) {
	var requested flow.Traffic
	var err error
	for _, candidate := range c.services[term] {
		if err := c.visits.take(ctx, candidate.traffic.RegionCount()+1); err != nil {
			return fm.ServiceRef{}, err
		}
		if !c.visible(candidate.reference, scope, c.serviceNames) {
			continue
		}
		if candidate.traffic.Empty() {
			return fm.ServiceRef{Kind: candidate.reference.kind, ID: candidate.reference.id}, nil
		}
		if requested.Empty() {
			requested, err = servicecoverage.FromTerms(ctx, []fm.ServiceTerm{term}, c.limits.MaxRegions)
			if err != nil {
				return fm.ServiceRef{}, err
			}
		}
		equal, err := candidate.traffic.Equal(requested, c.limits.MaxRegions)
		if err != nil {
			return fm.ServiceRef{}, err
		}
		if equal {
			return fm.ServiceRef{Kind: candidate.reference.kind, ID: candidate.reference.id}, nil
		}
	}
	id, err := c.names.object(ctx, generatedID("fm-s-", term), c.names.services)
	if err != nil {
		return fm.ServiceRef{}, err
	}
	object := fm.Object{ID: id, Name: string(id)}
	c.data.Services = append(c.data.Services, fm.ServiceRecord{Object: object, Terms: []fm.ServiceTerm{term}})
	candidate := catalogService{reference: catalogReference{kind: fm.ServiceObject, id: object.ID}}
	c.services[term] = append(c.services[term], candidate)
	c.recordName(c.serviceNames, candidate.reference, object)
	return fm.ServiceRef{Kind: fm.ServiceObject, ID: id}, nil
}
func (c *objectCatalog) match(ctx context.Context, box flow.TrafficRegion, q policy.Request) (fm.Match, error) {
	m := fm.Match{AnyFromZone: q.FromZone == "", AnyToZone: q.ToZone == ""}
	if !m.AnyFromZone {
		m.FromZones = []fm.ID{q.FromZone}
	}
	if !m.AnyToZone {
		m.ToZones = []fm.ID{q.ToZone}
	}
	source, err := c.ensureAddress(ctx, box.Source, m.FromZones, q.Scope)
	if err != nil {
		return fm.Match{}, err
	}
	destination, err := c.ensureAddress(ctx, box.Destination, m.ToZones, q.Scope)
	if err != nil {
		return fm.Match{}, err
	}
	service, err := c.ensureService(ctx, serviceTermFromRegion(box), q.Scope)
	if err != nil {
		return fm.Match{}, err
	}
	m.Sources = []fm.AddressRef{source}
	m.Destinations = []fm.AddressRef{destination}
	m.Services = []fm.ServiceRef{service}
	return m, nil
}
