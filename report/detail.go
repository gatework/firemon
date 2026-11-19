package report

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gatework/firemon"
)

// RuleDetail is the definition of a rule as configured, with every object
// it names expanded to its members, so that an operator can compare it
// with the device line by line.
type RuleDetail struct {
	Rule string `json:"rule"`
	Name string `json:"name,omitempty"`
	// Position is the one-based place in the rule list: rules match in
	// order, the first that matches decides.
	Position     int            `json:"position"`
	Action       firemon.Action `json:"action"`
	From         []string       `json:"from,omitempty"`
	To           []string       `json:"to,omitempty"`
	Source       []Object       `json:"source,omitempty"`
	Destination  []Object       `json:"destination,omitempty"`
	NegateSource bool           `json:"negate_source,omitempty"`
	NegateDest   bool           `json:"negate_destination,omitempty"`
	Services     []Object       `json:"services,omitempty"`
	Applications []string       `json:"applications,omitempty"`
	Schedule     *Object        `json:"schedule,omitempty"`
	Disabled     bool           `json:"disabled,omitempty"`
	Description  string         `json:"description,omitempty"`
}

// Object is a named object or an inline value. Values are its own
// entries; Members are the objects a group contains, expanded the same
// way.
type Object struct {
	Name    string   `json:"name,omitempty"`
	Values  []string `json:"values,omitempty"`
	Members []Object `json:"members,omitempty"`
	// Missing reports a name the configuration does not define.
	Missing bool `json:"missing,omitempty"`
}

// details returns the definitions of the rules with the given IDs, in
// rule order, each once.
func details(fw *firemon.Firewall, ids []string) []RuleDetail {
	if fw == nil || len(ids) == 0 {
		return nil
	}
	x := newExpander(fw.Config())
	var out []RuleDetail
	for _, r := range fw.Rules() {
		if !slices.Contains(ids, r.ID()) {
			continue
		}
		s := r.Spec()
		d := RuleDetail{
			Rule: s.ID, Name: s.Name, Position: r.Position() + 1, Action: s.Action,
			From: s.From, To: s.To, NegateSource: s.NegateSource, NegateDest: s.NegateDestination,
			Applications: s.Applications, Disabled: s.Disabled, Description: s.Description,
		}
		for _, a := range s.Source {
			d.Source = append(d.Source, x.address(a, 0))
		}
		for _, a := range s.Destination {
			d.Destination = append(d.Destination, x.address(a, 0))
		}
		for _, n := range s.Services {
			d.Services = append(d.Services, x.service(n, 0))
		}
		for _, e := range s.ServiceEntries {
			d.Services = append(d.Services, Object{Values: []string{e.String()}})
		}
		if s.Schedule != "" {
			o := x.schedule(s.Schedule)
			d.Schedule = &o
		}
		out = append(out, d)
	}
	return out
}

// maxDepth bounds group expansion; configurations do not nest deeper and
// a cycle stops there.
const maxDepth = 8

type expander struct {
	addrs     map[string]firemon.Address
	addrGrps  map[string]firemon.AddressGroup
	svcs      map[string]firemon.Service
	svcGrps   map[string]firemon.ServiceGroup
	schedules map[string]firemon.Schedule
}

func newExpander(cfg *firemon.Config) expander {
	x := expander{
		addrs: map[string]firemon.Address{}, addrGrps: map[string]firemon.AddressGroup{},
		svcs: map[string]firemon.Service{}, svcGrps: map[string]firemon.ServiceGroup{}, schedules: map[string]firemon.Schedule{},
	}
	for _, a := range cfg.Addresses {
		x.addrs[a.Name] = a
	}
	for _, g := range cfg.AddressGroups {
		x.addrGrps[g.Name] = g
	}
	for _, s := range cfg.Services {
		x.svcs[s.Name] = s
	}
	for _, g := range cfg.ServiceGroups {
		x.svcGrps[g.Name] = g
	}
	for _, s := range cfg.Schedules {
		x.schedules[s.Name] = s
	}
	return x
}

func (x expander) address(ref firemon.AddressRef, depth int) Object {
	if ref.IsInline() {
		return Object{Values: []string{ref.Entry.String()}}
	}
	return x.addressName(ref.Name, depth)
}

func (x expander) addressName(name string, depth int) Object {
	o := Object{Name: name}
	a, isAddr := x.addrs[name]
	g, isGroup := x.addrGrps[name]
	switch {
	case isAddr:
		o.Values = entryTexts(a.Entries)
		o.Values = append(o.Values, a.Invalid...)
	case isGroup:
		o.Values = entryTexts(g.Entries)
		if g.Filter != "" {
			o.Values = append(o.Values, "filter "+g.Filter)
		}
		if depth < maxDepth {
			for _, m := range g.Members {
				o.Members = append(o.Members, x.addressName(m, depth+1))
			}
		}
	default:
		o.Missing = true
	}
	return o
}

func (x expander) service(name string, depth int) Object {
	o := Object{Name: name}
	s, isSvc := x.svcs[name]
	g, isGroup := x.svcGrps[name]
	switch {
	case isSvc:
		for _, e := range s.Entries {
			o.Values = append(o.Values, e.String())
		}
		o.Values = append(o.Values, s.Invalid...)
	case isGroup:
		if depth < maxDepth {
			for _, m := range g.Members {
				o.Members = append(o.Members, x.service(m, depth+1))
			}
		}
	default:
		o.Missing = true
	}
	return o
}

func (x expander) schedule(name string) Object {
	s, ok := x.schedules[name]
	if !ok {
		return Object{Name: name, Missing: true}
	}
	o := Object{Name: name}
	for _, w := range s.Windows {
		o.Values = append(o.Values, windowText(w))
	}
	for _, r := range s.Recurrences {
		o.Values = append(o.Values, recurrenceText(r))
	}
	if s.Unsupported != "" {
		o.Values = append(o.Values, s.Unsupported)
	}
	return o
}

func entryTexts(es []firemon.AddressEntry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.String())
	}
	return out
}

func windowText(w firemon.TimeWindow) string {
	const layout = "2006-01-02 15:04:05"
	from, to := "", ""
	if !w.Start.IsZero() {
		from = w.Start.Format(layout)
	}
	if !w.End.IsZero() {
		to = w.End.Format(layout)
	}
	return from + " ~ " + to
}

func recurrenceText(r firemon.Recurrence) string {
	days := make([]string, len(r.Days))
	for i, d := range r.Days {
		days[i] = d.String()[:3]
	}
	day := "daily"
	if len(days) > 0 {
		day = strings.Join(days, ",")
	}
	clock := func(d time.Duration) string { return fmt.Sprintf("%02d:%02d", int(d.Hours()), int(d.Minutes())%60) }
	return day + " " + clock(r.Start) + "-" + clock(r.End)
}
