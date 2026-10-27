package srx

import (
	"context"
	"net/netip"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

type appTerm struct {
	protocol            uint16
	hasProtocol         bool
	source, destination []flow.Interval
	unsupported         []string
}
type application struct {
	object fm.Object
	terms  catalog[appTerm]
}

func bookPath(w []string) (scope string, rest []string, ok bool) {
	if begins(w, "set", "security", "address-book") && len(w) >= 5 {
		if w[3] == "global" {
			return "", w[4:], true
		}
		return "book:" + w[3], w[4:], true
	}
	if begins(w, "set", "security", "zones", "security-zone") && len(w) >= 7 && w[5] == "address-book" {
		return "zone:" + w[4], w[6:], true
	}
	return "", nil, false
}
func (p *parser) objects(ctx context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	defer tx.Rollback()
	var addresses catalog[fm.AddressRecord]
	var groups catalog[fm.AddressGroupRecord]
	var apps catalog[application]
	var serviceGroups catalog[fm.ServiceGroupRecord]
	d := fm.Data{}
	for _, row := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := row.Words
		if scope, rest, ok := bookPath(w); ok {
			switch {
			case len(rest) == 3 && rest[0] == "attach" && rest[1] == "zone" && strings.HasPrefix(scope, "book:") && scope != "book:global":
				p.books[rest[2]] = unique(p.books[rest[2]], scope)
				tx.Parse(row.Lines()...)
			case len(rest) >= 3 && rest[0] == "address":
				id := addressID(scope, rest[1])
				r := addresses.get(string(id))
				r.Object.ID, r.Name, r.Scope = id, rest[1], scope
				valid := false
				switch {
				case len(rest) == 3:
					a, err := addressRange(rest[2])
					if err == nil {
						if len(r.Ranges) > 0 && r.Ranges[0] != a {
							r.Unsupported = append(r.Unsupported, "conflicting address leaves")
						}
						r.Ranges = unique(r.Ranges, a)
						valid = true
					}
				case len(rest) == 6 && rest[2] == "range-address" && rest[4] == "to":
					a, e1 := netip.ParseAddr(rest[3])
					b, e2 := netip.ParseAddr(rest[5])
					rr := flow.Range{First: a, Last: b}
					if e1 == nil && e2 == nil && rr.Valid() {
						if len(r.Ranges) > 0 && r.Ranges[0] != rr {
							r.Unsupported = append(r.Unsupported, "conflicting address leaves")
						}
						r.Ranges = unique(r.Ranges, rr)
						valid = true
					}
				case len(rest) == 4 && rest[2] == "dns-name":
					r.FQDN = rest[3]
					valid = true
				}
				if valid {
					touch(&r.Object, row)
					tx.Parse(row.Lines()...)
				} else {
					r.Unsupported = append(r.Unsupported, "unsupported address leaf")
				}
			case len(rest) >= 2 && rest[0] == "address-set":
				id := addressID(scope, rest[1])
				r := groups.get(string(id))
				r.ID, r.Name, r.Scope = id, rest[1], scope
				if len(rest) == 4 && (rest[2] == "address" || rest[2] == "address-set") {
					kind := fm.AddressObject
					if rest[2] == "address-set" {
						kind = fm.AddressGroupObject
					}
					r.Members = unique(r.Members, fm.AddressRef{Kind: kind, ID: addressID(scope, rest[3])})
					touch(&r.Object, row)
					tx.Parse(row.Lines()...)
				} else {
					r.Unsupported = append(r.Unsupported, "unsupported address set member")
				}
			}
			continue
		}
		if begins(w, "set", "applications", "application") && len(w) >= 5 {
			a := apps.get(w[3])
			a.object = fm.Object{ID: fm.ID(w[3]), Name: w[3], Spans: a.object.Spans}
			rest := w[4:]
			name := "$default"
			if len(rest) >= 3 && rest[0] == "term" {
				name = rest[1]
				rest = rest[2:]
			}
			t := a.terms.get(name)
			valid := false
			if len(rest) >= 2 {
				switch rest[0] {
				case "protocol":
					if len(rest) == 2 {
						n, ok := protocol(rest[1])
						if ok {
							if t.hasProtocol && n != t.protocol {
								t.unsupported = append(t.unsupported, "conflicting application protocols")
							}
							t.protocol, t.hasProtocol = n, true
							valid = true
						}
					}
				case "source-port", "destination-port":
					if values, ok := list(rest[1:]); ok {
						parsed := make([]flow.Interval, 0, len(values))
						valid = true
						for _, value := range values {
							interval, ok := ports(value)
							if !ok {
								valid = false
								break
							}
							parsed = unique(parsed, interval)
						}
						if valid {
							for _, interval := range parsed {
								if rest[0] == "source-port" {
									t.source = unique(t.source, interval)
								} else {
									t.destination = unique(t.destination, interval)
								}
							}
						}
					}
				}
			}
			if valid {
				touch(&a.object, row)
				tx.Parse(row.Lines()...)
			} else {
				t.unsupported = append(t.unsupported, "unsupported application term condition")
			}
			continue
		}
		if begins(w, "set", "applications", "application-set") && len(w) >= 5 {
			r := serviceGroups.get(w[3])
			r.ID, r.Name = fm.ID(w[3]), w[3]
			if len(w) == 6 && (w[4] == "application" || w[4] == "application-set") {
				kind := fm.ServiceObject
				if w[4] == "application-set" {
					kind = fm.ServiceGroupObject
				}
				r.Members = unique(r.Members, fm.ServiceRef{Kind: kind, ID: fm.ID(w[5])})
				touch(&r.Object, row)
				tx.Parse(row.Lines()...)
			} else {
				r.Unsupported = append(r.Unsupported, "unsupported application set member")
			}
		}
	}
	for name, attached := range p.books {
		if len(attached) > 1 {
			d.Diagnostics = append(d.Diagnostics, diagnostic("ambiguous-address-book", "zone has multiple attached address books"))
		}
		found := false
		for _, zone := range p.data.Zones {
			found = found || zone.Name == name
		}
		if !found {
			d.Diagnostics = append(d.Diagnostics, diagnostic("missing-address-book-zone", "address book attached to an undefined zone"))
		}
		local := "zone:" + name
		for _, a := range addresses.entries {
			if a.Scope == local {
				d.Diagnostics = append(d.Diagnostics, diagnostic("ambiguous-address-book", "zone mixes local and attached address books"))
				break
			}
		}
		for _, g := range groups.entries {
			if g.Scope == local {
				d.Diagnostics = append(d.Diagnostics, diagnostic("ambiguous-address-book", "zone mixes local and attached address books"))
				break
			}
		}
	}
	for _, name := range addresses.names {
		r := addresses.entries[name]
		if groups.entries[name] != nil {
			d.Diagnostics = append(d.Diagnostics, diagnostic("ambiguous-address", "address and address set share a native name"))
		}
		d.Addresses = append(d.Addresses, *r)
	}
	for _, name := range groups.names {
		d.AddressGroups = append(d.AddressGroups, *groups.entries[name])
	}
	for _, name := range apps.names {
		a := apps.entries[name]
		r := fm.ServiceRecord{Object: a.object}
		if len(a.terms.names) > 1 && a.terms.entries["$default"] != nil {
			r.Unsupported = append(r.Unsupported, "mixed application default and named terms")
		}
		for _, name := range a.terms.names {
			t := a.terms.entries[name]
			r.Unsupported = append(r.Unsupported, t.unsupported...)
			if !t.hasProtocol {
				r.Unsupported = append(r.Unsupported, "missing application protocol")
				continue
			}
			if (len(t.source) > 0 || len(t.destination) > 0) && t.protocol != 6 && t.protocol != 17 && t.protocol != 132 {
				r.Unsupported = append(r.Unsupported, "ports on a non-transport protocol")
				continue
			}
			if len(t.source) == 0 {
				t.source = []flow.Interval{{High: 65535}}
			}
			if len(t.destination) == 0 {
				t.destination = []flow.Interval{{High: 65535}}
			}
			if len(t.source) > 4096 || len(t.destination) > 4096 || len(t.source)*len(t.destination) > 4096-len(r.Terms) {
				return policyLimit()
			}
			for _, src := range t.source {
				for _, dst := range t.destination {
					r.Terms = append(r.Terms, fm.ServiceTerm{Protocol: flow.Interval{Low: t.protocol, High: t.protocol}, SourcePort: src, DestinationPort: dst, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}})
				}
			}
		}
		if serviceGroups.entries[name] != nil {
			d.Diagnostics = append(d.Diagnostics, diagnostic("ambiguous-application", "application and set share a native name"))
		}
		d.Services = append(d.Services, r)
	}
	for _, name := range serviceGroups.names {
		d.ServiceGroups = append(d.ServiceGroups, *serviceGroups.entries[name])
	}
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	p.data = s.Data()
	p.addresses = make(map[fm.ID]fm.AddressRef)
	for _, a := range p.data.Addresses {
		p.addresses[a.ID] = fm.AddressRef{Kind: fm.AddressObject, ID: a.ID}
	}
	for _, g := range p.data.AddressGroups {
		p.addresses[g.ID] = fm.AddressRef{Kind: fm.AddressGroupObject, ID: g.ID}
	}
	return nil
}

func (p *parser) lookupAddress(zone, name string) fm.AddressRef {
	scopes := append([]string{"zone:" + zone}, p.books[zone]...)
	scopes = append(scopes, "")
	for _, scope := range scopes {
		if ref, ok := p.addresses[addressID(scope, name)]; ok {
			return ref
		}
	}
	return fm.AddressRef{}
}

func (p *parser) addressRef(zone, name string, d *fm.Data) fm.AddressRef {
	if ref := p.lookupAddress(zone, name); ref.ID != "" {
		return ref
	}
	if name == "any-ipv4" || name == "any-ipv6" {
		id := fm.ID("$" + name)
		for _, a := range d.Addresses {
			if a.ID == id {
				return fm.AddressRef{Kind: fm.AddressObject, ID: id}
			}
		}
		prefix := "0.0.0.0/0"
		if name == "any-ipv6" {
			prefix = "::/0"
		}
		r, _ := addressRange(prefix)
		d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: id, Name: name}, Ranges: []flow.Range{r}})
		return fm.AddressRef{Kind: fm.AddressObject, ID: id}
	}
	return fm.AddressRef{Kind: fm.AddressObject, ID: nativeID("missing-address", zone, name)}
}
func (p *parser) serviceRef(name string) fm.ServiceRef {
	for _, g := range p.data.ServiceGroups {
		if g.ID == fm.ID(name) {
			return fm.ServiceRef{Kind: fm.ServiceGroupObject, ID: g.ID}
		}
	}
	return fm.ServiceRef{Kind: fm.ServiceObject, ID: fm.ID(name)}
}
