package hillstone

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

func literal(value string) (flow.AddressRange, error) {
	if parts := strings.Split(value, "-"); len(parts) == 2 {
		a, e := netip.ParseAddr(parts[0])
		b, e2 := netip.ParseAddr(parts[1])
		r := flow.AddressRange{First: a, Last: b}
		if e != nil || e2 != nil || !r.Valid() {
			return flow.AddressRange{}, flow.ErrRange
		}
		return r, nil
	}
	v, err := prefix([]string{value})
	if err != nil {
		return flow.AddressRange{}, err
	}
	return flow.PrefixRange(v)
}
func number(value string, max int) (uint16, bool) {
	v, err := strconv.Atoi(value)
	return uint16(v), err == nil && v >= 0 && v <= max
}
func port(words []string) (flow.Interval, bool) {
	if len(words) < 1 || len(words) > 2 {
		return flow.Interval{}, false
	}
	a, ok := number(words[0], 65535)
	b := a
	if len(words) == 2 {
		var valid bool
		b, valid = number(words[1], 65535)
		ok = ok && valid
	}
	return flow.Interval{Low: a, High: b}, ok && a <= b
}
func term(w []string) (fm.ServiceTerm, bool) {
	full := flow.Interval{Low: 0, High: 65535}
	octet := flow.Interval{Low: 0, High: 255}
	r := fm.ServiceTerm{SourcePort: full, DestinationPort: full, ICMPType: octet, ICMPCode: octet}
	if len(w) == 2 && w[0] == "protocol" {
		n, ok := number(w[1], 255)
		r.Protocol = flow.Interval{Low: n, High: n}
		return r, ok
	}
	if len(w) == 1 && w[0] == "icmp" {
		r.Protocol = flow.Interval{Low: 1, High: 1}
		return r, true
	}
	if len(w) < 3 || w[1] != "dst-port" {
		return r, false
	}
	protocols := map[string]uint16{"tcp": 6, "udp": 17, "sctp": 132}
	protocol, ok := protocols[w[0]]
	if !ok {
		return r, false
	}
	r.Protocol = flow.Interval{Low: protocol, High: protocol}
	split := slices.Index(w, "src-port")
	end := len(w)
	if split >= 0 {
		end = split
	}
	r.DestinationPort, ok = port(w[2:end])
	if split >= 0 {
		var valid bool
		r.SourcePort, valid = port(w[split+1:])
		ok = ok && valid
	}
	return r, ok
}
func (p *parser) objects(ctx context.Context, s *config.Builder) error {
	definitions, err := p.definitions(ctx, "address", "service", "servgroup")
	if err != nil {
		return err
	}
	if err := p.inventoryObjects(ctx, definitions); err != nil {
		return err
	}
	for _, d := range definitions {
		switch d.kind {
		case "address":
			err = p.parseAddress(ctx, s, d)
		case "service":
			err = p.parseService(ctx, s, d)
		case "servgroup":
			err = p.parseServiceGroup(ctx, s, d)
		}
		if err != nil {
			return err
		}
	}
	// Schedules retain their existing per-block interpretation.
	for _, n := range p.nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if n.block.Kind == "schedule" && namedHeader(n.block.Header.Words) {
			if err := p.parseSchedule(ctx, s, n); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *parser) inventoryObjects(ctx context.Context, definitions []definition) error {
	// Inventory every reopening before resolving forward group references.
	for _, d := range definitions {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch d.kind {
		case "address":
			kind := fm.AddressObject
			for _, b := range d.blocks {
				if err := ctx.Err(); err != nil {
					return err
				}
				for _, line := range b.Members {
					if err := ctx.Err(); err != nil {
						return err
					}
					if len(line.Words) == 2 && line.Words[0] == "member" {
						kind = fm.AddressGroupObject
					}
				}
			}
			p.addressKinds[d.id] = kind
		case "service":
			p.serviceKinds[d.id] = fm.ServiceObject
		case "servgroup":
			// Native lookup prefers a declared service to a same-name group,
			// independent of which declaration appeared first.
			if p.serviceKinds[d.id] != fm.ServiceObject {
				p.serviceKinds[d.id] = fm.ServiceGroupObject
			}
		}
	}
	return ctx.Err()
}

func (p *parser) parseAddress(ctx context.Context, s *config.Builder, d definition) error {
	r := fm.AddressRecord{Object: d.object()}
	g := fm.AddressGroupRecord{}
	tx := s.Begin()
	defer tx.Rollback()
	if err := d.walk(ctx, tx, &r.Object, func(w []string) bool {
		if len(w) == 2 && w[0] == "ip" {
			if v, err := literal(w[1]); err == nil {
				r.Ranges = append(r.Ranges, v)
				return true
			}
		}
		if len(w) == 3 && w[0] == "range" {
			if v, err := literal(w[1] + "-" + w[2]); err == nil {
				r.Ranges = append(r.Ranges, v)
				return true
			}
		}
		if len(w) == 2 && w[0] == "host" {
			r.FQDN = w[1]
			return true
		}
		if len(w) == 2 && w[0] == "member" {
			g.Members = append(g.Members, p.addressRef(w[1]))
			return true
		}
		return ancillary(w)
	}); err != nil {
		return err
	}
	delta := fm.Data{}
	if len(g.Members) == 0 {
		delta.Addresses = append(delta.Addresses, r)
	} else {
		g.Object = r.Object
		if len(r.Ranges) > 0 || r.FQDN != "" {
			leaf := r
			leaf.ID = fm.ID("$members:" + string(d.id))
			g.Members = append(g.Members, fm.AddressRef{Kind: fm.AddressObject, ID: leaf.ID})
			delta.Addresses = append(delta.Addresses, leaf)
		}
		delta.AddressGroups = append(delta.AddressGroups, g)
	}
	tx.Emit(delta)
	return s.Commit(tx)
}

func (p *parser) parseService(ctx context.Context, s *config.Builder, d definition) error {
	r := fm.ServiceRecord{Object: d.object()}
	tx := s.Begin()
	defer tx.Rollback()
	if err := d.walk(ctx, tx, &r.Object, func(w []string) bool {
		v, ok := term(w)
		if ok {
			r.Terms = append(r.Terms, v)
		}
		return ok || ancillary(w)
	}); err != nil {
		return err
	}
	tx.Emit(fm.Data{Services: []fm.ServiceRecord{r}})
	return s.Commit(tx)
}

func (p *parser) parseServiceGroup(ctx context.Context, s *config.Builder, d definition) error {
	r := fm.ServiceGroupRecord{Object: d.object()}
	tx := s.Begin()
	defer tx.Rollback()
	if err := d.walk(ctx, tx, &r.Object, func(w []string) bool {
		if len(w) == 2 && w[0] == "service" {
			r.Members = append(r.Members, p.serviceRef(w[1]))
			return true
		}
		return ancillary(w)
	}); err != nil {
		return err
	}
	tx.Emit(fm.Data{ServiceGroups: []fm.ServiceGroupRecord{r}})
	return s.Commit(tx)
}

func (p *parser) parseSchedule(ctx context.Context, s *config.Builder, n node) error {
	r := fm.ScheduleRecord{Object: object(n)}
	tx := begin(s, n.block)
	defer tx.Rollback()
	for _, l := range n.block.Members {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := l.Words
		ok := ancillary(w)
		if len(w) == 7 && w[0] == "absolute" && w[1] == "start" && w[4] == "end" {
			for _, layout := range []string{"01/02/2006 15:04", "01/02/2006 15:04:05"} {
				window, zone, err := s.ScheduleWindow(layout, w[2]+" "+w[3], w[5]+" "+w[6])
				if err == nil {
					r.Windows = append(r.Windows, window)
					r.Timezone = zone
					ok = true
					break
				}
			}
			if !ok {
				r.Unsupported = append(r.Unsupported, "native schedule clock or window not established")
			}

		}
		consume(tx, l, ok, &r.Object)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx.Emit(fm.Data{Schedules: []fm.ScheduleRecord{r}})
	return s.Commit(tx)
}

func (p *parser) addressRef(name string) fm.AddressRef {
	kind := p.addressKinds[fm.ID(name)]
	if kind == fm.UnknownObject {
		kind = fm.AddressObject
	}
	return fm.AddressRef{Kind: kind, ID: fm.ID(name)}
}
func (p *parser) serviceRef(name string) fm.ServiceRef {
	kind := p.serviceKinds[fm.ID(name)]
	if kind == fm.UnknownObject {
		kind = fm.ServiceObject
	}
	return fm.ServiceRef{Kind: kind, ID: fm.ID(name)}
}
