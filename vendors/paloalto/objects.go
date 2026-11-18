package paloalto

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// address parses: address NAME ip-netmask V | ip-range A-B | fqdn F |
// description D | tag T.
func (s *state) address(p *path, st statement) {
	name := p.next()
	i, ok := s.addresses[name]
	if !ok {
		i = len(s.cfg.Addresses)
		s.addresses[name] = i
		s.cfg.Addresses = append(s.cfg.Addresses, firemon.Address{Name: name})
	}
	a := &s.cfg.Addresses[i]
	switch kind := p.next(); kind {
	case "ip-netmask", "ip-range", "fqdn":
		value := p.scalar()
		e, ok := entry(kind, value)
		if !ok {
			s.diagnose(st, "invalid address value")
			return
		}
		a.Entries = append(a.Entries, e)
		if kind == "ip-netmask" {
			s.hostBits[name] = value
		}
	case "description":
		a.Description = p.scalar()
	case "tag", "ip-wildcard":
		if kind == "ip-wildcard" {
			s.diagnose(st, "wildcard addresses are not supported")
		}
	default:
		s.diagnose(st, "unrecognized address attribute")
	}
}

// entry parses the value of an address object or an inline rule operand.
func entry(kind, value string) (firemon.AddressEntry, bool) {
	switch kind {
	case "ip-netmask":
		if p, err := netip.ParsePrefix(value); err == nil {
			return firemon.PrefixEntry(p), true
		}
		a, err := netip.ParseAddr(value)
		return firemon.HostEntry(a), err == nil
	case "ip-range":
		from, to, ok := strings.Cut(value, "-")
		a, err1 := netip.ParseAddr(from)
		b, err2 := netip.ParseAddr(to)
		return firemon.RangeEntry(a, b), ok && err1 == nil && err2 == nil && a.Is4() == b.Is4() && !b.Less(a)
	case "fqdn":
		return firemon.FQDNEntry(value), value != ""
	default:
		return firemon.AddressEntry{}, false
	}
}

// inlineEntry classifies a rule operand that names no object: an address,
// a prefix or a range.
func inlineEntry(value string) (firemon.AddressEntry, bool) {
	if strings.Contains(value, "-") {
		return entry("ip-range", value)
	}
	return entry("ip-netmask", value)
}

// addressGroup parses: address-group NAME static [ MEMBERS ] |
// dynamic filter EXPR | description D | tag T.
func (s *state) addressGroup(p *path, st statement) {
	name := p.next()
	i, ok := s.groups[name]
	if !ok {
		i = len(s.cfg.AddressGroups)
		s.groups[name] = i
		s.cfg.AddressGroups = append(s.cfg.AddressGroups, firemon.AddressGroup{Name: name})
	}
	g := &s.cfg.AddressGroups[i]
	switch p.next() {
	case "static":
		g.Members = append(g.Members, p.value()...)
	case "dynamic":
		if p.next() == "filter" {
			g.Filter = p.scalar()
		}
		if g.Filter == "" {
			g.Filter = "dynamic"
		}
	case "description":
		g.Description = p.scalar()
	case "tag":
	default:
		s.diagnose(st, "unrecognized address-group attribute")
	}
}

// service parses: service NAME protocol tcp|udp|sctp port P[,P...]
// [source-port P] [override ...] | description D.
func (s *state) service(p *path, st statement) {
	name := p.next()
	i, ok := s.services[name]
	if !ok {
		i = len(s.cfg.Services)
		s.services[name] = i
		s.cfg.Services = append(s.cfg.Services, firemon.Service{Name: name})
	}
	svc := &s.cfg.Services[i]
	switch p.next() {
	case "protocol":
		entries, ok := protocolEntries(p)
		if !ok {
			s.diagnose(st, "invalid service")
			return
		}
		svc.Entries = append(svc.Entries, entries...)
	case "description":
		svc.Description = p.scalar()
	case "tag":
	default:
		s.diagnose(st, "unrecognized service attribute")
	}
}

// protocolEntries parses "tcp port 80,8000-8080 [source-port 1024-65535]".
// A statement setting only "override" yields no entries.
func protocolEntries(p *path) ([]firemon.ServiceEntry, bool) {
	proto, err := traffic.ParseProtocol(p.next())
	if err != nil {
		return nil, false
	}
	var dst, src []traffic.PortRange
	for !p.done() {
		switch p.next() {
		case "port":
			if dst, err = portList(p.next()); err != nil {
				return nil, false
			}
		case "source-port":
			if src, err = portList(p.next()); err != nil {
				return nil, false
			}
		case "override":
			p.value()
		default:
			return nil, false
		}
	}
	if len(src) == 0 {
		src = []traffic.PortRange{traffic.AnyPort}
	}
	var out []firemon.ServiceEntry
	for _, d := range dst {
		for _, sp := range src {
			out = append(out, firemon.ServiceEntry{Protocol: proto, Src: sp, Dst: d})
		}
	}
	return out, true
}

func portList(text string) ([]traffic.PortRange, error) {
	var out []traffic.PortRange
	for part := range strings.SplitSeq(text, ",") {
		r, err := traffic.ParsePortRange(part)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// serviceGroup parses: service-group NAME members [ MEMBERS ].
func (s *state) serviceGroup(p *path, st statement) {
	name := p.next()
	i, ok := s.svcGroups[name]
	if !ok {
		i = len(s.cfg.ServiceGroups)
		s.svcGroups[name] = i
		s.cfg.ServiceGroups = append(s.cfg.ServiceGroups, firemon.ServiceGroup{Name: name})
	}
	switch p.next() {
	case "members":
		s.cfg.ServiceGroups[i].Members = append(s.cfg.ServiceGroups[i].Members, p.value()...)
	case "tag":
	default:
		s.diagnose(st, "unrecognized service-group attribute")
	}
}

// schedule parses: schedule NAME schedule-type non-recurring
// YYYY/MM/DD@HH:MM-YYYY/MM/DD@HH:MM | recurring daily [ HH:MM-HH:MM ] |
// recurring weekly DAY [ HH:MM-HH:MM ].
func (s *state) schedule(p *path, st statement) {
	name := p.next()
	i, ok := s.schedules[name]
	if !ok {
		i = len(s.cfg.Schedules)
		s.schedules[name] = i
		s.cfg.Schedules = append(s.cfg.Schedules, firemon.Schedule{Name: name})
	}
	sch := &s.cfg.Schedules[i]
	if p.next() != "schedule-type" {
		return
	}
	var ok2 bool
	switch p.next() {
	case "non-recurring":
		ok2 = s.windows(sch, p.value())
	case "recurring":
		ok2 = recurring(sch, p)
	}
	if !ok2 {
		sch.Unsupported = "unrecognized schedule"
		s.diagnose(st, "unsupported schedule")
	}
}

func (s *state) windows(sch *firemon.Schedule, values []string) bool {
	for _, v := range values {
		from, to, ok := strings.Cut(v, "-")
		start, err1 := time.ParseInLocation("2006/1/2@15:04", from, s.loc)
		end, err2 := time.ParseInLocation("2006/1/2@15:04", to, s.loc)
		if !ok || err1 != nil || err2 != nil {
			return false
		}
		sch.Windows = append(sch.Windows, firemon.TimeWindow{Start: start, End: end})
	}
	return len(values) > 0
}

func recurring(sch *firemon.Schedule, p *path) bool {
	var days []time.Weekday
	switch p.next() {
	case "daily":
	case "weekly":
		d, ok := weekday(p.next())
		if !ok {
			return false
		}
		days = []time.Weekday{d}
	default:
		return false
	}
	values := p.value()
	for _, v := range values {
		from, to, ok := strings.Cut(v, "-")
		start, ok1 := clock(from)
		end, ok2 := clock(to)
		if !ok || !ok1 || !ok2 {
			return false
		}
		sch.Recurrences = append(sch.Recurrences, firemon.Recurrence{Days: days, Start: start, End: end})
	}
	return len(values) > 0
}

func weekday(text string) (time.Weekday, bool) {
	for d := time.Sunday; d <= time.Saturday; d++ {
		if strings.EqualFold(text, d.String()) {
			return d, true
		}
	}
	return 0, false
}

func clock(text string) (time.Duration, bool) {
	h, m, ok := strings.Cut(text, ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || hh > 24 || mm > 59 {
		return 0, false
	}
	return time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute, true
}
