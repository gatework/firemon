package paloalto

import (
	"context"

	"slices"

	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

func (p *parser) objects(ctx context.Context, s *config.Builder) error {
	d := fm.Data{}
	tx := s.Begin()
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
						a.Ranges = []flow.AddressRange{v}
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
		d.Addresses = append(d.Addresses, addresses[name])
	}
	for _, name := range keys(groups) {
		g := groups[name]
		for i := range g.Members {
			g.Members[i].Kind = fm.AddressObject
			if _, ok := groups[string(g.Members[i].ID)]; ok {
				g.Members[i].Kind = fm.AddressGroupObject
			}
		}
		d.AddressGroups = append(d.AddressGroups, g)
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
		d.Services = append(d.Services, r)
	}
	builtins := map[string][]flow.Interval{"service-http": {{Low: 80, High: 80}, {Low: 8080, High: 8080}}, "service-https": {{Low: 443, High: 443}}}
	for _, name := range keys(builtins) {
		ports := builtins[name]
		if _, ok := services[name]; !ok {
			d.Services = append(d.Services, fm.ServiceRecord{Object: fm.Object{ID: fm.ID(name), Name: name}, Terms: serviceTerms("tcp", full, ports)})
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
		d.ServiceGroups = append(d.ServiceGroups, g)
	}
	for _, name := range keys(schedules) {
		d.Schedules = append(d.Schedules, schedules[name])
	}
	tx.Emit(d)
	return s.Commit(tx)
}
