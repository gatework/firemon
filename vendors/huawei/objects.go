package huawei

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

// Indexed native members replace a prior member with the same ID. Automatic
// IDs cannot be inferred when mixed with explicit IDs in a command capture.
type members[T any] struct {
	values []T
	index  map[uint64]int
	mode   uint8
}

func (m *members[T]) put(id string, value T) bool {
	mode := uint8(1)
	if id != "" {
		mode = 2
	}
	if m.mode != 0 && m.mode != mode {
		return false
	}
	m.mode = mode
	if id == "" {
		m.values = append(m.values, value)
		return true
	}
	n, ok := number(id, 0, 1<<32-1)
	if !ok {
		return false
	}
	if m.index == nil {
		m.index = make(map[uint64]int)
	}
	if i, ok := m.index[n]; ok {
		m.values[i] = value
	} else {
		m.index[n] = len(m.values)
		m.values = append(m.values, value)
	}
	return true
}
func member(w []string) (string, []string) {
	if len(w) > 0 {
		if _, ok := number(w[0], 0, 1<<32-1); ok {
			return w[0], w[1:]
		}
	}
	return "", w
}
func setHeader(w []string) (string, string, error) {
	if len(w) < 3 || w[2] == "" || strings.EqualFold(w[2], "any") || strings.EqualFold(w[2], "all") || strings.HasPrefix(w[2], "$") {
		return "", "", fmt.Errorf("invalid object name")
	}
	if len(w) == 3 {
		return w[2], "", nil
	}
	if (len(w) == 5 || len(w) == 6) && w[3] == "type" && (w[4] == "object" || w[4] == "group") {
		if len(w) == 6 {
			if _, ok := number(w[5], 0, 1<<32-1); !ok {
				return "", "", fmt.Errorf("invalid object number")
			}
		}
		return w[2], w[4], nil
	}
	return "", "", fmt.Errorf("unsupported object header")
}
func addressRange(w []string) (flow.Range, bool) {
	if len(w) == 3 && w[0] == "range" {
		a, ok1 := ipv4(w[1])
		b, ok2 := ipv4(w[2])
		r := flow.Range{First: a, Last: b}
		return r, ok1 && ok2 && r.Valid()
	}
	if len(w) == 1 {
		w = []string{w[0], "32"}
	}
	if len(w) == 3 && w[1] == "mask" {
		w = []string{w[0], w[2]}
	}
	p, ok := prefix(w)
	if !ok || p != p.Masked() {
		return flow.Range{}, false
	}
	r, e := flow.PrefixRange(p)
	return r, e == nil
}
func term(proto uint16) fm.ServiceTerm {
	return fm.ServiceTerm{Protocol: flow.Interval{Low: proto, High: proto}, SourcePort: flow.Interval{High: 65535}, DestinationPort: flow.Interval{High: 65535}, ICMPType: flow.Interval{High: 255}, ICMPCode: flow.Interval{High: 255}}
}
func protocol(v string) (uint16, bool) {
	switch v {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "sctp":
		return 132, true
	case "icmp":
		return 1, true
	case "icmpv6":
		return 58, true
	case "gre":
		return 47, true
	case "esp":
		return 50, true
	case "ah":
		return 51, true
	}
	n, ok := number(v, 1, 255)
	return uint16(n), ok
}
func serviceTerms(w []string) ([]fm.ServiceTerm, bool) {
	if len(w) == 0 {
		return nil, false
	}
	proto, ok := protocol(w[0])
	if !ok {
		return nil, false
	}
	w = w[1:]
	ports := map[string][]flow.Interval{}
	base := term(proto)
	for len(w) > 0 {
		key := w[0]
		w = w[1:]
		if key != "source-port" && key != "destination-port" || ports[key] != nil || (proto != 6 && proto != 17 && proto != 132) {
			return nil, false
		}
		for len(w) > 0 {
			a, ok := number(w[0], 0, 65535)
			if !ok {
				break
			}
			w = w[1:]
			b := a
			if len(w) > 0 && w[0] == "to" {
				if len(w) < 2 {
					return nil, false
				}
				var ok bool
				b, ok = number(w[1], a, 65535)
				if !ok {
					return nil, false
				}
				w = w[2:]
			}
			ports[key] = append(ports[key], flow.Interval{Low: uint16(a), High: uint16(b)})
		}
		if len(ports[key]) == 0 {
			return nil, false
		}
	}
	src, dst := ports["source-port"], ports["destination-port"]
	if len(src) == 0 {
		src = []flow.Interval{base.SourcePort}
	}
	if len(dst) == 0 {
		dst = []flow.Interval{base.DestinationPort}
	}
	if len(src) > 4096/len(dst) {
		return nil, false
	}
	terms := make([]fm.ServiceTerm, 0, len(src)*len(dst))
	for _, a := range src {
		for _, b := range dst {
			t := base
			t.SourcePort, t.DestinationPort = a, b
			terms = append(terms, t)
		}
	}
	return terms, true
}
func (p *parser) addressRef(name string) fm.AddressRef {
	if r, ok := p.addresses[name]; ok {
		return r
	}
	return fm.AddressRef{Kind: fm.AddressObject, ID: fm.ID(name)}
}
func (p *parser) serviceRef(name string) fm.ServiceRef {
	if r, ok := p.services[name]; ok {
		return r
	}
	return fm.ServiceRef{Kind: fm.ServiceObject, ID: fm.ID(name)}
}
func (p *parser) literalAddress(d *fm.Data, r flow.Range) fm.AddressRef {
	id := fm.ID("$address:" + r.First.String() + "-" + r.Last.String())
	key := string(id)
	if ref, ok := p.addresses[key]; ok {
		return ref
	}
	o := object(key)
	o.Scope = "literal"
	o.Inline = true
	d.Addresses = append(d.Addresses, fm.AddressRecord{Object: o, Ranges: []flow.Range{r}})
	ref := fm.AddressRef{Kind: fm.AddressObject, ID: id}
	p.addresses[key] = ref
	return ref
}
func (p *parser) literalService(d *fm.Data, terms []fm.ServiceTerm) fm.ServiceRef {
	var key strings.Builder
	key.WriteString("$service:")
	for _, t := range terms {
		fmt.Fprintf(&key, "%d/%d-%d:%d-%d;", t.Protocol.Low, t.SourcePort.Low, t.SourcePort.High, t.DestinationPort.Low, t.DestinationPort.High)
	}
	name := key.String()
	if ref, ok := p.services[name]; ok {
		return ref
	}
	o := object(name)
	o.Scope = "literal"
	o.Inline = true
	d.Services = append(d.Services, fm.ServiceRecord{Object: o, Terms: terms})
	ref := fm.ServiceRef{Kind: fm.ServiceObject, ID: o.ID}
	p.services[name] = ref
	return ref
}
func (p *parser) objects(ctx context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	defer tx.Rollback()
	var d fm.Data
	addresses, err := p.grouped("address", setHeader)
	if err != nil {
		return err
	}
	services, err := p.grouped("service", setHeader)
	if err != nil {
		return err
	}
	for _, g := range addresses {
		kind := fm.AddressObject
		if g.kind == "group" {
			kind = fm.AddressGroupObject
		}
		p.addresses[g.name] = fm.AddressRef{Kind: kind, ID: fm.ID(g.name)}
	}
	for _, g := range services {
		kind := fm.ServiceObject
		if g.kind == "group" {
			kind = fm.ServiceGroupObject
		}
		p.services[g.name] = fm.ServiceRef{Kind: kind, ID: fm.ID(g.name)}
	}
	type addressMember struct {
		ref   string
		value flow.Range
	}
	for _, g := range addresses {
		o := object(g.name)
		var items members[addressMember]
		err := walk(ctx, tx, &o, g, func(row config.Statement) bool {
			w := row.Words
			if w[0] == "description" && len(w) > 1 {
				return true
			}
			if w[0] != "address" {
				return false
			}
			id, rest := member(w[1:])
			var a addressMember
			if len(rest) == 2 && rest[0] == "address-set" && g.kind == "group" {
				a.ref = rest[1]
			} else {
				var ok bool
				a.value, ok = addressRange(rest)
				if !ok {
					return false
				}
			}
			return items.put(id, a)
		})
		if err != nil {
			return err
		}
		if g.kind == "object" {
			a := fm.AddressRecord{Object: o}
			for _, item := range items.values {
				a.Ranges = append(a.Ranges, item.value)
			}
			d.Addresses = append(d.Addresses, a)
		} else {
			a := fm.AddressGroupRecord{Object: o}
			for _, item := range items.values {
				if item.ref != "" {
					a.Members = append(a.Members, p.addressRef(item.ref))
				} else {
					a.Members = append(a.Members, p.literalAddress(&d, item.value))
				}
			}
			d.AddressGroups = append(d.AddressGroups, a)
		}
	}
	type serviceMember struct {
		ref   string
		terms []fm.ServiceTerm
	}
	for _, g := range services {
		o := object(g.name)
		var items members[serviceMember]
		err := walk(ctx, tx, &o, g, func(row config.Statement) bool {
			w := row.Words
			if w[0] == "description" && len(w) > 1 {
				return true
			}
			if w[0] != "service" {
				return false
			}
			id, rest := member(w[1:])
			var a serviceMember
			for i, v := range rest {
				if v == "description" && i < len(rest)-1 {
					rest = rest[:i]
					break
				}
			}
			if g.kind == "group" {
				if len(rest) != 2 || rest[0] != "service-set" {
					return false
				}
				a.ref = rest[1]
			} else {
				if !has(rest, "protocol") {
					return false
				}
				var ok bool
				a.terms, ok = serviceTerms(rest[1:])
				if !ok {
					return false
				}
			}
			return items.put(id, a)
		})
		if err != nil {
			return err
		}
		if g.kind == "object" {
			a := fm.ServiceRecord{Object: o}
			for _, item := range items.values {
				a.Terms = append(a.Terms, item.terms...)
			}
			d.Services = append(d.Services, a)
		} else {
			a := fm.ServiceGroupRecord{Object: o}
			for _, item := range items.values {
				a.Members = append(a.Members, p.serviceRef(item.ref))
			}
			d.ServiceGroups = append(d.ServiceGroups, a)
		}
	}
	// Local clocks and recurring windows require a captured time-zone contract.
	// Retain native schedules as unresolved objects, never as unrestricted time.
	for _, b := range p.blocks {
		if b.Kind == "schedule" && len(b.Header.Words) == 2 {
			o := object(b.Header.Words[1])
			o.Unsupported = []string{"native schedule time zone/window semantics"}
			d.Schedules = append(d.Schedules, fm.ScheduleRecord{Object: o})
		}
	}
	return p.commit(s, tx, d)
}

func portText(p flow.Interval) string {
	if p.Low == p.High {
		return strconv.Itoa(int(p.Low))
	}
	return fmt.Sprintf("%d to %d", p.Low, p.High)
}
