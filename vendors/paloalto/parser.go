// Package paloalto parses native PAN-OS configuration paths without flattening unknown conditions.
package paloalto

import (
	"context"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

type row struct {
	source config.Statement
	words  []string
	shared bool
}
type parser struct {
	rows     []row
	session  *config.Session
	data     fm.Data
	graph    *fm.Firewall
	location *time.Location
	prefixes map[fm.ID]netip.Prefix
}

func Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor = "paloalto"
	metadata.ParserVersion = "paloalto-go-2"
	var c *config.Cursor
	var statements []config.Statement
	var native *xmlInput
	var err error
	if strings.HasPrefix(strings.TrimLeft(source.Text, " \t\r\n\ufeff"), "<") {
		native, statements, err = xmlStatements(ctx, source)
		if err != nil {
			return nil, err
		}
		c = native.document.Cursor
	} else {
		c, err = config.NewCursor(source, config.Limits{})
		if err != nil {
			return nil, err
		}
		statements, err = config.Statements(ctx, c)
		if err != nil {
			return nil, err
		}
	}
	p := &parser{session: config.NewSession(c, metadata), prefixes: make(map[fm.ID]netip.Prefix)}
	for _, line := range statements {
		w := line.Words
		if len(w) == 0 {
			p.rows = append(p.rows, row{source: line})
			continue
		}
		if w[0] != "set" {
			continue
		}
		w = w[1:]
		shared := false
		if len(w) > 0 && w[0] == "shared" {
			shared = true
			w = w[1:]
		}
		if len(w) > 1 && w[0] == "vsys" {
			if w[1] != "vsys1" {
				continue
			}
			w = w[2:]
		}
		p.rows = append(p.rows, row{line, w, shared})
	}
	stages := []config.Stage{{Name: "objects", Run: p.objects}, {Name: "network", Requires: []string{"objects"}, Run: p.network}, {Name: "rules", Requires: []string{"network"}, Run: p.rules}, {Name: "nat", Requires: []string{"rules"}, Run: p.nat}}
	if native != nil {
		stages = append(stages, config.Stage{Name: "xml-evidence", Requires: []string{"nat"}, Run: native.finish})
	}
	if err = p.session.Run(ctx, stages); err != nil {
		return nil, err
	}
	return fm.Seal(p.session.Data())
}
func values(w []string) []string {
	out := make([]string, 0, len(w))
	for _, v := range w {
		if v != "[" && v != "]" {
			out = append(out, v)
		}
	}
	return out
}
func object(name string, r row) fm.Object {
	return fm.Object{ID: fm.ID(name), Name: name, Spans: []fm.Span{r.source.Span}}
}
func address(value string) (flow.Range, error) {
	if parts := strings.Split(value, "-"); len(parts) == 2 {
		a, e := netip.ParseAddr(parts[0])
		b, e2 := netip.ParseAddr(parts[1])
		r := flow.Range{First: a, Last: b}
		if e != nil || e2 != nil || !r.Valid() {
			return flow.Range{}, flow.ErrRange
		}
		return r, nil
	}
	p, err := hostPrefix(value)
	if err != nil {
		return flow.Range{}, err
	}
	return flow.PrefixRange(p)
}
func hostPrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		return netip.ParsePrefix(value)
	}
	a, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
func ports(value string) ([]flow.Interval, error) {
	var out []flow.Interval
	for _, part := range strings.Split(value, ",") {
		ends := strings.Split(part, "-")
		if len(ends) > 2 {
			return nil, fmt.Errorf("invalid ports")
		}
		lo, err := strconv.ParseUint(ends[0], 10, 16)
		if err != nil {
			return nil, err
		}
		hi := lo
		if len(ends) == 2 {
			hi, err = strconv.ParseUint(ends[1], 10, 16)
			if err != nil {
				return nil, err
			}
		}
		if lo > hi {
			return nil, fmt.Errorf("reversed port interval")
		}
		out = append(out, flow.Interval{Low: uint16(lo), High: uint16(hi)})
	}
	return out, nil
}
func serviceTerms(protocol string, src, dst []flow.Interval) []fm.ServiceTerm {
	var terms []fm.ServiceTerm
	n := map[string]uint16{"tcp": 6, "udp": 17}[protocol]
	for _, a := range src {
		for _, b := range dst {
			terms = append(terms, fm.ServiceTerm{Protocol: flow.Interval{Low: n, High: n}, SourcePort: a, DestinationPort: b, ICMPType: flow.Interval{Low: 0, High: 255}, ICMPCode: flow.Interval{Low: 0, High: 255}})
		}
	}
	return terms
}
func keys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}
func (p *parser) objects(_ context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	addresses := make(map[string]fm.AddressRecord)
	groups := make(map[string]fm.AddressGroupRecord)
	services := make(map[string]fm.ServiceRecord)
	serviceGroups := make(map[string]fm.ServiceGroupRecord)
	schedules := make(map[string]fm.ScheduleRecord)
	local := make(map[string]bool)
	type serviceDraft struct {
		protocol string
		src, dst []flow.Interval
	}
	serviceParts := make(map[string]serviceDraft)
	for _, r := range p.rows {
		w := r.words
		if len(w) > 1 && !r.shared && slices.Contains([]string{"address", "address-group", "service", "service-group", "schedule"}, w[0]) {
			local[w[0]+"/"+w[1]] = true
		}
		if len(w) == 4 && slices.Equal(w[:3], []string{"deviceconfig", "system", "timezone"}) {
			if location, err := time.LoadLocation(w[3]); err == nil {
				p.location = location
				tx.Parse(r.source.Lines()...)
			}
		}
	}
	for _, r := range p.rows {
		w := r.words
		if len(w) == 0 {
			tx.Ignore("blank line", r.source.Lines()...)
			continue
		}
		if len(w) < 3 {
			continue
		}
		if r.shared && local[w[0]+"/"+w[1]] {
			tx.Ignore("shared declaration overridden by local object", r.source.Lines()...)
			continue
		}
		name, field := w[1], w[2]
		rest := values(w[3:])
		ok := false
		switch w[0] {
		case "address":
			a, exists := addresses[name]
			if !exists {
				a.Object = object(name, r)
			}
			switch field {
			case "ip-netmask", "ip-range":
				if len(rest) == 1 {
					if v, err := address(rest[0]); err == nil {
						a.Ranges = []flow.Range{v}
						ok = true
					}
					if field == "ip-netmask" {
						if prefix, err := hostPrefix(rest[0]); err == nil {
							p.prefixes[a.ID] = prefix
						}
					}
				}
			case "fqdn":
				if len(rest) == 1 {
					a.FQDN = rest[0]
					ok = true
				}
			case "description", "tag":
				ok = true
			}
			if !ok {
				a.Unsupported = append(a.Unsupported, "unsupported address field")
			}
			addresses[name] = a
		case "address-group":
			g, exists := groups[name]
			if !exists {
				g.Object = object(name, r)
			}
			switch field {
			case "static":
				for _, member := range rest {
					g.Members = append(g.Members, fm.AddressRef{ID: fm.ID(member)})
				}
				ok = true
			case "description", "tag":
				ok = true
			}
			if !ok {
				g.Unsupported = append(g.Unsupported, "dynamic or unsupported address group")
			}
			groups[name] = g
		case "service":
			a, exists := services[name]
			if !exists {
				a.Object = object(name, r)
			}
			draft := serviceParts[name]
			if field == "protocol" && len(rest) == 3 && (rest[0] == "tcp" || rest[0] == "udp") {
				draft.protocol = rest[0]
				parsed, err := ports(rest[2])
				if err == nil {
					switch rest[1] {
					case "port":
						draft.dst = parsed
						ok = true
					case "source-port":
						draft.src = parsed
						ok = true
					}
				}
			} else if field == "description" || field == "tag" {
				ok = true
			}
			if !ok {
				a.Unsupported = append(a.Unsupported, "unsupported service field")
			}
			services[name] = a
			serviceParts[name] = draft
		case "service-group":
			g, exists := serviceGroups[name]
			if !exists {
				g.Object = object(name, r)
			}
			if field == "members" {
				for _, member := range rest {
					g.Members = append(g.Members, fm.ServiceRef{ID: fm.ID(member)})
				}
				ok = true
			} else if field == "description" || field == "tag" {
				ok = true
			}
			if !ok {
				g.Unsupported = append(g.Unsupported, "unsupported service group")
			}
			serviceGroups[name] = g
		case "schedule":
			a, exists := schedules[name]
			if !exists {
				a.Object = object(name, r)
			}
			if field == "schedule-type" && len(rest) >= 2 && rest[0] == "non-recurring" && p.location != nil {
				ok = true
				for _, value := range rest[1:] {
					parts := strings.Split(value, "-")
					if len(parts) != 2 {
						ok = false
						break
					}
					start, e := time.ParseInLocation("2006/01/02@15:04", parts[0], p.location)
					end, e2 := time.ParseInLocation("2006/01/02@15:04", parts[1], p.location)
					if e != nil || e2 != nil || !start.Before(end) {
						ok = false
						break
					}
					a.Windows = append(a.Windows, fm.TimeWindow{Start: start.UTC(), End: end.UTC()})
				}
				a.Timezone = p.location.String()
			}
			if !ok {
				a.Unsupported = append(a.Unsupported, "unsupported schedule or missing timezone")
			}
			schedules[name] = a
		default:
			continue
		}
		if ok {
			tx.Parse(r.source.Lines()...)
		}
	}
	for _, name := range keys(addresses) {
		p.data.Addresses = append(p.data.Addresses, addresses[name])
	}
	for _, name := range keys(groups) {
		g := groups[name]
		for i := range g.Members {
			g.Members[i].Kind = fm.AddressObject
			if _, ok := groups[string(g.Members[i].ID)]; ok {
				g.Members[i].Kind = fm.AddressGroupObject
			}
		}
		p.data.AddressGroups = append(p.data.AddressGroups, g)
	}
	full := []flow.Interval{{Low: 0, High: 65535}}
	for _, name := range keys(services) {
		r := services[name]
		part := serviceParts[name]
		if len(part.src) == 0 {
			part.src = full
		}
		if len(part.dst) == 0 || part.protocol == "" {
			r.Unsupported = append(r.Unsupported, "incomplete service")
		}
		r.Terms = serviceTerms(part.protocol, part.src, part.dst)
		p.data.Services = append(p.data.Services, r)
	}
	builtins := map[string][]flow.Interval{"service-http": {{Low: 80, High: 80}, {Low: 8080, High: 8080}}, "service-https": {{Low: 443, High: 443}}}
	for _, name := range keys(builtins) {
		ports := builtins[name]
		if _, ok := services[name]; !ok {
			p.data.Services = append(p.data.Services, fm.ServiceRecord{Object: fm.Object{ID: fm.ID(name), Name: name}, Terms: serviceTerms("tcp", full, ports)})
		}
	}
	for _, name := range keys(serviceGroups) {
		g := serviceGroups[name]
		for i := range g.Members {
			g.Members[i].Kind = fm.ServiceObject
			if _, ok := serviceGroups[string(g.Members[i].ID)]; ok {
				g.Members[i].Kind = fm.ServiceGroupObject
			}
		}
		p.data.ServiceGroups = append(p.data.ServiceGroups, g)
	}
	for _, name := range keys(schedules) {
		p.data.Schedules = append(p.data.Schedules, schedules[name])
	}
	tx.Emit(p.data)
	return s.Commit(tx)
}
func (p *parser) network(_ context.Context, s *config.Session) error {
	tx := s.Cursor.Begin()
	interfaces := make(map[string]fm.InterfaceRecord)
	zones := make(map[string]fm.ZoneRecord)
	routes := make(map[string]fm.RouteRecord)
	bindings := make(map[string]string)
	vrfs := make(map[string]string)
	for _, row := range p.rows {
		w := row.words
		if len(w) < 3 {
			continue
		}
		ok := false
		if w[0] == "zone" && len(w) >= 6 && w[2] == "network" && w[3] == "layer3" {
			name := w[1]
			zones[name] = fm.ZoneRecord{Object: object(name, row)}
			for _, i := range values(w[4:]) {
				bindings[i] = name
			}
			ok = true
		}
		if w[0] == "zone" && len(w) == 5 && w[2] == "network" && w[3] == "layer3" {
			name := w[1]
			zones[name] = fm.ZoneRecord{Object: object(name, row)}
			bindings[w[4]] = name
			ok = true
		}
		if len(w) >= 8 && slices.Equal(w[:3], []string{"network", "interface", "ethernet"}) && w[4] == "layer3" && w[5] == "ip" {
			name := w[3]
			r := interfaces[name]
			if r.ID == "" {
				r.Object = object(name, row)
			}
			for _, value := range values(w[6:]) {
				prefix, err := hostPrefix(value)
				if err != nil {
					prefix = p.prefixes[fm.ID(value)]
				}
				if !prefix.IsValid() {
					r.Unsupported = append(r.Unsupported, "unresolved interface address")
				} else {
					r.Addresses = append(r.Addresses, prefix)
				}
			}
			interfaces[name] = r
			ok = true
		}
		if len(w) == 7 && slices.Equal(w[:3], []string{"network", "interface", "ethernet"}) && w[4] == "layer3" && w[5] == "ip" {
			name := w[3]
			r := interfaces[name]
			if r.ID == "" {
				r.Object = object(name, row)
			}
			prefix, err := hostPrefix(w[6])
			if err != nil {
				prefix = p.prefixes[fm.ID(w[6])]
			}
			if !prefix.IsValid() {
				r.Unsupported = append(r.Unsupported, "unresolved interface address")
			} else {
				r.Addresses = append(r.Addresses, prefix)
			}
			interfaces[name] = r
			ok = true
		}
		if len(w) >= 5 && w[0] == "network" && w[1] == "virtual-router" {
			vrf := w[2]
			if w[3] == "interface" {
				for _, i := range values(w[4:]) {
					vrfs[i] = vrf
				}
				ok = true
			}
			if len(w) >= 9 && slices.Equal(w[3:6], []string{"routing-table", "ip", "static-route"}) {
				name := w[6]
				r := routes[name]
				if r.ID == "" {
					r.Object = object(name, row)
					r.Scope = vrf
				}
				switch w[7] {
				case "destination":
					if v, err := hostPrefix(w[8]); err == nil {
						r.Destination = v.Masked()
						ok = true
					}
				case "interface":
					r.Interface = fm.ID(w[8])
					ok = true
				case "nexthop":
					if len(w) == 10 && w[8] == "ip-address" {
						if v, err := netip.ParseAddr(w[9]); err == nil {
							r.NextHop = v
							ok = true
						}
					}
				case "metric":
					if n, err := strconv.ParseUint(w[8], 10, 32); err == nil {
						r.Metric = uint32(n)
						ok = true
					}
				}
				if !ok {
					r.Unsupported = append(r.Unsupported, "unsupported route field")
				}
				routes[name] = r
			}
		}
		if ok {
			tx.Parse(row.source.Lines()...)
		}
	}
	d := fm.Data{}
	for _, name := range keys(zones) {
		d.Zones = append(d.Zones, zones[name])
	}
	for _, name := range keys(interfaces) {
		r := interfaces[name]
		r.Zone = fm.ID(bindings[name])
		r.Scope = vrfs[name]
		d.Interfaces = append(d.Interfaces, r)
		for i, prefix := range r.Addresses {
			d.Routes = append(d.Routes, fm.RouteRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("connected:%s:%d", name, i)), Scope: r.Scope}, Destination: prefix.Masked(), Interface: r.ID, Direct: true})
		}
	}
	for _, name := range keys(routes) {
		r := routes[name]
		if !r.Destination.IsValid() {
			d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Object: r.ID, Code: "incomplete-route"})
			continue
		}
		d.Routes = append(d.Routes, r)
	}
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	p.data = s.Data()
	return nil
}
