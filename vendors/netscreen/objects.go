package netscreen

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

type addressGroup struct {
	record  fm.AddressGroupRecord
	zone    string
	members []string
}
type serviceGroup struct {
	record  fm.ServiceGroupRecord
	members []string
}

func (p *parser) objects(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	defer tx.Rollback()
	var addresses catalog[fm.AddressRecord]
	var groups catalog[addressGroup]
	var services catalog[fm.ServiceRecord]
	var serviceGroups catalog[serviceGroup]
	p.addresses = make(map[fm.ID]fm.AddressRef)
	p.services = make(map[string]fm.ServiceRef)
	// Native builtins exist independently of whether a user policy references
	// them. Removing the last reference must not appear to delete an object.
	anyRange, _ := flow.PrefixRange(netip.MustParsePrefix("0.0.0.0/0"))
	*addresses.get("$any-ipv4") = fm.AddressRecord{Object: object("$any-ipv4", "Any", "builtin"), Ranges: []flow.AddressRange{anyRange}}
	p.addresses["$any-ipv4"] = fm.AddressRef{Kind: fm.AddressObject, ID: "$any-ipv4"}
	for _, r := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.scope != "root" {
			continue
		}
		w := r.Words
		switch {
		case begins(w, "set", "address") && len(w) >= 5:
			scope := addressScope(w[2])
			id := addressID(scope, w[3])
			a := addresses.get(string(id))
			a.Object = object(id, w[3], scope)
			v, n, ok := prefix(w[4:])
			if ok && v == v.Masked() && (len(w) == 4+n || len(w) == 5+n) {
				rr, _ := flow.PrefixRange(v)
				a.Ranges = []flow.AddressRange{rr}
				touch(&a.Object, r)
				tx.Parse(r.Lines()...)
			} else {
				a.Unsupported = append(a.Unsupported, "unsupported address declaration")
			}
			p.addresses[id] = fm.AddressRef{Kind: fm.AddressObject, ID: id}
		case begins(w, "set", "group", "address") && len(w) >= 5:
			scope := addressScope(w[3])
			id := addressID(scope, w[4])
			g := groups.get(string(id))
			g.record.ID, g.record.Name, g.record.Scope, g.zone = id, w[4], scope, w[3]
			valid := len(w) == 5
			if len(w) == 7 && w[5] == "add" {
				g.members = unique(g.members, w[6])
				valid = true
			}
			if len(w) == 7 && w[5] == "comment" {
				valid = true
			}
			if valid {
				touch(&g.record.Object, r)
				tx.Parse(r.Lines()...)
			} else {
				g.record.Unsupported = append(g.record.Unsupported, "unsupported address group member")
			}
			if previous := p.addresses[id]; previous.Kind == fm.AddressObject {
				g.record.Unsupported = append(g.record.Unsupported, "address/group namespace collision")
			} else {
				p.addresses[id] = fm.AddressRef{Kind: fm.AddressGroupObject, ID: id}
			}
		case begins(w, "set", "service") && len(w) >= 4:
			name := w[2]
			service := services.get(name)
			service.ID, service.Name = fm.ID(name), name
			valid := false
			if len(w) == 9 || len(w) == 11 && w[9] == "timeout" {
				proto, ok1 := protocol(w[4])
				sp, ok2 := ports(w[6])
				dp, ok3 := ports(w[8])
				ok4 := true
				if len(w) == 11 {
					_, e := strconv.ParseUint(w[10], 10, 32)
					ok4 = e == nil
				}
				if (w[3] == "protocol" || w[3] == "+") && w[5] == "src-port" && w[7] == "dst-port" && ok1 && ok2 && ok3 && ok4 {
					term := fm.ServiceTerm{Protocol: flow.Interval{Low: proto, High: proto}, SourcePort: sp, DestinationPort: dp, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}
					if w[3] == "protocol" {
						service.Terms = []fm.ServiceTerm{term}
					} else {
						service.Terms = unique(service.Terms, term)
					}
					valid = true
				}
			}
			if len(w) == 5 && w[3] == "timeout" && len(service.Terms) > 0 {
				_, e := strconv.ParseUint(w[4], 10, 32)
				valid = e == nil
			}
			if valid {
				touch(&service.Object, r)
				tx.Parse(r.Lines()...)
			} else {
				service.Unsupported = append(service.Unsupported, "unsupported service condition")
			}
			p.services[name] = fm.ServiceRef{Kind: fm.ServiceObject, ID: service.ID}
		case begins(w, "set", "group", "service") && len(w) >= 4:
			g := serviceGroups.get(w[3])
			g.record.ID, g.record.Name = fm.ID(w[3]), w[3]
			valid := len(w) == 4
			if len(w) == 6 && w[4] == "add" {
				g.members = unique(g.members, w[5])
				valid = true
			}
			if len(w) == 6 && w[4] == "comment" {
				valid = true
			}
			if valid {
				touch(&g.record.Object, r)
				tx.Parse(r.Lines()...)
			} else {
				g.record.Unsupported = append(g.record.Unsupported, "unsupported service group member")
			}
		}
	}
	for _, name := range serviceGroups.names {
		if p.services[name].ID == "" {
			p.services[name] = fm.ServiceRef{Kind: fm.ServiceGroupObject, ID: fm.ID(name)}
		}
	}
	d := fm.Data{}
	for _, name := range addresses.names {
		d.Addresses = append(d.Addresses, *addresses.entries[name])
	}
	for _, name := range groups.names {
		g := groups.entries[name]
		for _, member := range g.members {
			g.record.Members = append(g.record.Members, p.addressRef(g.zone, member, &d))
		}
		d.AddressGroups = append(d.AddressGroups, g.record)
	}
	for _, name := range services.names {
		d.Services = append(d.Services, *services.entries[name])
	}
	for _, name := range serviceGroups.names {
		g := serviceGroups.entries[name]
		for _, member := range g.members {
			g.record.Members = append(g.record.Members, p.serviceRef(member))
		}
		d.ServiceGroups = append(d.ServiceGroups, g.record)
	}
	return p.commit(s, tx, d)
}

func (p *parser) lookupAddress(zone, name string) fm.AddressRef {
	name = mappedName(name)
	for _, scope := range []string{addressScope(zone), ""} {
		if ref := p.addresses[addressID(scope, name)]; ref.ID != "" {
			return ref
		}
	}
	return fm.AddressRef{}
}
func (p *parser) addressRef(zone, name string, d *fm.Data) fm.AddressRef {
	if ref := p.lookupAddress(zone, name); ref.ID != "" {
		return ref
	}
	if strings.EqualFold(name, "Any") || strings.EqualFold(name, "Any-IPv4") {
		id := fm.ID("$any-ipv4")
		if _, ok := p.addresses[id]; !ok {
			r, _ := flow.PrefixRange(netip.MustParsePrefix("0.0.0.0/0"))
			d.Addresses = append(d.Addresses, fm.AddressRecord{Object: object(id, "Any", "builtin"), Ranges: []flow.AddressRange{r}})
			p.addresses[id] = fm.AddressRef{Kind: fm.AddressObject, ID: id}
		}
		return p.addresses[id]
	}
	return fm.AddressRef{Kind: fm.UnknownObject, ID: addressID(addressScope(zone), name)}
}
func (p *parser) serviceRef(name string) fm.ServiceRef {
	if ref := p.services[name]; ref.ID != "" {
		return ref
	}
	return fm.ServiceRef{Kind: fm.UnknownObject, ID: fm.ID(name)}
}
func (p *parser) addAddress(r *fm.RuleRecord, source bool, name string, d *fm.Data) {
	if source {
		r.Match.Sources = unique(r.Match.Sources, p.addressRef(string(r.Match.FromZones[0]), name, d))
	} else {
		r.Match.Destinations = unique(r.Match.Destinations, p.addressRef(string(r.Match.ToZones[0]), name, d))
	}
}
func (p *parser) addService(r *fm.RuleRecord, name string) {
	if strings.EqualFold(name, "ANY") && p.services[name].ID == "" {
		r.Match.AnyService = true
	} else {
		r.Match.Services = unique(r.Match.Services, p.serviceRef(name))
	}
}

func globalZone(zones []fm.ID) bool { return slices.Contains(zones, fm.ID("Global")) }
