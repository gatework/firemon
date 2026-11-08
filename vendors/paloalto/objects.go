package paloalto

import (
	"context"
	"errors"
	"slices"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

func (p *parser) objects(ctx context.Context, s *config.Builder) error {
	d := fm.Data{}
	tx := s.Begin()
	defer tx.Rollback()
	remaining := s.Content().Limits().MaxServiceTerms
	addresses := make(map[string]fm.AddressRecord)
	groups := make(map[string]fm.AddressGroupRecord)
	services := make(map[string]fm.ServiceRecord)
	serviceGroups := make(map[string]fm.ServiceGroupRecord)
	schedules := make(map[string]fm.ScheduleRecord)
	scheduleKinds := make(map[string]string)
	local := make(map[string]bool)
	type serviceDraft struct {
		protocol string
		src, dst []flow.Interval
	}
	serviceParts := make(map[string]serviceDraft)
	for _, r := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := r.words
		if len(w) > 1 && !r.shared && slices.Contains([]string{"address", "address-group", "service", "service-group", "schedule"}, w[0]) {
			local[w[0]+"/"+w[1]] = true
		}
		if len(w) == 4 && slices.Equal(w[:3], []string{"deviceconfig", "system", "timezone"}) {
			if _, err := time.LoadLocation(w[3]); err == nil {
				tx.Parse(r.source.Lines()...)
			}
		}
	}
	for _, r := range p.rows {
		if err := ctx.Err(); err != nil {
			return err
		}
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
					if err := ctx.Err(); err != nil {
						return err
					}
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
				parsed, err := ports(ctx, rest[2])
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
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
					if err := ctx.Err(); err != nil {
						return err
					}
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
			if field == "schedule-type" && len(rest) >= 2 {
				kind := rest[0]
				if kind == "recurring" {
					kind += "/" + rest[1]
				}
				if previous := scheduleKinds[name]; previous == "" || previous == kind {
					ok = parseSchedule(s, &a, rest) == nil
					scheduleKinds[name] = kind
				}
			}
			if !ok {
				a.Unsupported = append(a.Unsupported, "unsupported schedule or missing capture clock")
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
		if err := ctx.Err(); err != nil {
			return err
		}
		d.Addresses = append(d.Addresses, addresses[name])
	}
	for _, name := range keys(groups) {
		if err := ctx.Err(); err != nil {
			return err
		}
		g := groups[name]
		for i := range g.Members {
			if err := ctx.Err(); err != nil {
				return err
			}
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
		var err error
		r.Terms, err = serviceTerms(ctx, part.protocol, part.src, part.dst, &remaining)
		if err != nil {
			return err
		}
		d.Services = append(d.Services, r)
	}
	builtins := map[string][]flow.Interval{"service-http": {{Low: 80, High: 80}, {Low: 8080, High: 8080}}, "service-https": {{Low: 443, High: 443}}}
	for _, name := range keys(builtins) {
		ports := builtins[name]
		if _, ok := services[name]; !ok {
			terms, err := serviceTerms(ctx, "tcp", full, ports, &remaining)
			if err != nil {
				return err
			}
			d.Services = append(d.Services, fm.ServiceRecord{Object: fm.Object{ID: fm.ID(name), Name: name}, Terms: terms})
		}
	}
	for _, name := range keys(serviceGroups) {
		if err := ctx.Err(); err != nil {
			return err
		}
		g := serviceGroups[name]
		for i := range g.Members {
			if err := ctx.Err(); err != nil {
				return err
			}
			g.Members[i].Kind = fm.ServiceObject
			if _, ok := serviceGroups[string(g.Members[i].ID)]; ok {
				g.Members[i].Kind = fm.ServiceGroupObject
			}
		}
		d.ServiceGroups = append(d.ServiceGroups, g)
	}
	for _, name := range keys(schedules) {
		if err := ctx.Err(); err != nil {
			return err
		}
		d.Schedules = append(d.Schedules, schedules[name])
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx.Emit(d)
	return s.Commit(tx)
}
