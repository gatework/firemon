package firemon

import "slices"

// RuleSource returns the configuration text of a rule as the device wrote
// it, preceded by the objects it names: addresses, services and schedules,
// a group's members before the group, each once, the way a configuration
// defines before it uses. Objects without recorded text (predefined ones)
// are left out. False when the rule has no recorded text.
func (c *Config) RuleSource(id string) ([]string, bool) {
	i := slices.IndexFunc(c.Rules, func(r SecurityRule) bool { return r.ID == id })
	if i < 0 {
		return nil, false
	}
	rule, ok := c.Source[SourceKey(SourceRule, id)]
	if !ok {
		return nil, false
	}
	r := c.Rules[i]
	w := sourceWriter{c: c, seen: map[string]bool{}}
	for _, a := range slices.Concat(r.Source, r.Destination) {
		if a.Name != "" {
			w.address(a.Name, 0)
		}
	}
	for _, s := range r.Services {
		w.service(s, 0)
	}
	if r.Schedule != "" {
		w.emit(SourceSchedule, r.Schedule)
	}
	return append(w.out, rule...), true
}

// sourceWriter collects object text in definition order.
type sourceWriter struct {
	c    *Config
	seen map[string]bool
	out  []string
}

// maxSourceDepth stops group expansion on cycles.
const maxSourceDepth = 8

func (w *sourceWriter) address(name string, depth int) {
	if depth > maxSourceDepth || w.seen["a:"+name] {
		return
	}
	w.seen["a:"+name] = true
	if w.predefinedAddress(name) {
		return // built into the device: nothing to define
	}
	if i := slices.IndexFunc(w.c.AddressGroups, func(g AddressGroup) bool { return g.Name == name }); i >= 0 {
		for _, m := range w.c.AddressGroups[i].Members {
			w.address(m, depth+1)
		}
		if w.emit(SourceAddressGroup, name) {
			return
		}
	}
	w.emit(SourceAddress, name) // StoneOS groups are address blocks too
}

func (w *sourceWriter) service(name string, depth int) {
	if depth > maxSourceDepth || w.seen["s:"+name] {
		return
	}
	w.seen["s:"+name] = true
	if slices.ContainsFunc(w.c.Services, func(s Service) bool { return s.Name == name && s.Predefined }) ||
		slices.ContainsFunc(w.c.ServiceGroups, func(g ServiceGroup) bool { return g.Name == name && g.Predefined }) {
		return
	}
	if i := slices.IndexFunc(w.c.ServiceGroups, func(g ServiceGroup) bool { return g.Name == name }); i >= 0 {
		for _, m := range w.c.ServiceGroups[i].Members {
			w.service(m, depth+1)
		}
		if w.emit(SourceServiceGroup, name) {
			return
		}
	}
	w.emit(SourceService, name)
}

// emit appends an object's text; false when none is recorded.
func (w *sourceWriter) emit(kind, name string) bool {
	lines, ok := w.c.Source[SourceKey(kind, name)]
	if ok {
		w.out = append(w.out, lines...)
	}
	return ok
}

func (w *sourceWriter) predefinedAddress(name string) bool {
	return slices.ContainsFunc(w.c.Addresses, func(a Address) bool { return a.Name == name && a.Predefined }) ||
		slices.ContainsFunc(w.c.AddressGroups, func(g AddressGroup) bool { return g.Name == name && g.Predefined })
}
