package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
	"slices"
	"strings"
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

func addressVisible(d *fm.Data, a fm.AddressRecord, zones []fm.ID) bool {
	name := a.Name
	if name == "" {
		name = string(a.ID)
	}
	contexts := zones
	if len(contexts) == 0 {
		for _, z := range d.Zones {
			contexts = append(contexts, z.ID)
		}
	}
	if len(contexts) == 0 {
		return a.Scope == ""
	}
	for _, id := range contexts {
		scope, found := "", false
		for _, z := range d.Zones {
			if z.ID == id {
				scope, found = z.AddressScope, true
				break
			}
		}
		if !found || a.Scope != "" && a.Scope != scope {
			return false
		}
		if a.Scope != "" || scope == "" {
			continue
		}
		// A local object or group can shadow a globally available address name.
		for _, other := range d.Addresses {
			if other.Scope == scope && (other.Name == name || other.Name == "" && string(other.ID) == name) {
				return false
			}
		}
		for _, other := range d.AddressGroups {
			if other.Scope == scope && (other.Name == name || other.Name == "" && string(other.ID) == name) {
				return false
			}
		}
	}
	return true
}

func ensureAddress(d *fm.Data, r flow.Range, zones []fm.ID) fm.AddressRef {
	for _, a := range d.Addresses {
		if len(a.Ranges) == 1 && a.Ranges[0] == r && a.FQDN == "" && a.VIP == (fm.NATRef{}) && len(a.Unsupported) == 0 && addressVisible(d, a, zones) {
			return fm.AddressRef{Kind: fm.AddressObject, ID: a.ID}
		}
	}
	id := generatedID("fm-a-", r)
	for {
		collision := slices.ContainsFunc(d.Addresses, func(a fm.AddressRecord) bool { return a.ID == id || a.Name == string(id) }) || slices.ContainsFunc(d.AddressGroups, func(g fm.AddressGroupRecord) bool { return g.ID == id || g.Name == string(id) })
		if !collision {
			break
		}
		id += "-new"
	}
	d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id, Name: string(id)}, Ranges: []flow.Range{r}})
	return fm.AddressRef{Kind: fm.AddressObject, ID: id}
}

func serviceOf(b flow.Box) fm.ServiceTerm {
	return fm.ServiceTerm{Protocol: b.Protocol, SourcePort: b.SourcePort, DestinationPort: b.DestinationPort, ICMPType: b.ICMPType, ICMPCode: b.ICMPCode}
}

func ensureService(d *fm.Data, term fm.ServiceTerm) fm.ServiceRef {
	for _, s := range d.Services {
		if s.Scope == "" && len(s.Terms) == 1 && s.Terms[0] == term && len(s.Unsupported) == 0 {
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

func (p Planner) appendCandidate(ctx context.Context, fw *fm.Firewall, rule fm.RuleRecord, gap flow.Traffic) (*fm.Firewall, []Change, Cost, error) {
	d := fw.Export()
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
	for _, box := range gap.Boxes() {
		addresses, _ := flow.NewSet(box.Source)
		if !src.Contains(addresses) {
			ref := ensureAddress(&d, box.Source, rule.Match.FromZones)
			if !slices.Contains(change.Sources, ref) {
				change.Sources = append(change.Sources, ref)
				rule.Match.Sources = append(rule.Match.Sources, ref)
			}
			src = src.Union(addresses)
		}
		addresses, _ = flow.NewSet(box.Destination)
		if !dst.Contains(addresses) {
			ref := ensureAddress(&d, box.Destination, rule.Match.ToZones)
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
		var from, to []fm.ID
		if q.FromZone != "" {
			from = []fm.ID{q.FromZone}
		}
		if q.ToZone != "" {
			to = []fm.ID{q.ToZone}
		}
		m := fm.Match{Sources: []fm.AddressRef{ensureAddress(&d, box.Source, from)}, Destinations: []fm.AddressRef{ensureAddress(&d, box.Destination, to)}, Services: []fm.ServiceRef{ensureService(&d, serviceOf(box))}}
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
