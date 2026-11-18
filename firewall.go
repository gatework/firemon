package firemon

import (
	"cmp"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/gatework/firemon/traffic"
)

// ErrInvalidConfig reports a configuration that cannot be compiled at all.
var ErrInvalidConfig = errors.New("firemon: invalid configuration")

// Issue records a construct that compiled but cannot be evaluated exactly.
type Issue struct {
	Object string `json:"object"`
	Reason string `json:"reason"`
}

// String writes "object: reason".
func (i Issue) String() string { return i.Object + ": " + i.Reason }

// Firewall is a compiled, immutable firewall. It is safe for concurrent use.
type Firewall struct {
	cfg        *Config
	loc        *time.Location
	addresses  map[string]resolved[traffic.AddressSet]
	services   map[string]resolved[traffic.ServiceSet]
	zones      map[string]Zone
	interfaces map[string]Interface
	tables     map[string]*RoutingTable
	rules      []*Rule
	nat        []*NATRule
	statics    []*StaticMapping
	issues     []Issue
}

// Compile resolves every reference in cfg and returns the evaluable
// firewall. cfg is copied; later changes to it do not affect the result.
// Unknown or unresolvable references do not fail compilation: they are
// reported by Issues and make the affected rules undecidable.
func Compile(cfg *Config) (*Firewall, error) {
	if cfg == nil || !cfg.Vendor.Valid() {
		return nil, fmt.Errorf("%w: unsupported vendor", ErrInvalidConfig)
	}
	cfg = cfg.Clone()
	fw := &Firewall{
		cfg:        cfg,
		loc:        cmp.Or(cfg.Location, time.UTC),
		zones:      make(map[string]Zone, len(cfg.Zones)),
		interfaces: make(map[string]Interface, len(cfg.Interfaces)),
	}
	fw.indexNetwork()
	res := newResolver(cfg)
	fw.compileObjects(res)
	fw.compileRules(res)
	fw.compileNAT(res)
	var issues []Issue
	fw.tables, issues = buildRoutingTables(cfg, fw.interfaces)
	fw.issues = append(fw.issues, issues...)
	return fw, nil
}

// Vendor returns the device vendor.
func (fw *Firewall) Vendor() Vendor { return fw.cfg.Vendor }

// Hostname returns the device hostname.
func (fw *Firewall) Hostname() string { return fw.cfg.Hostname }

// Semantics returns the vendor evaluation semantics.
func (fw *Firewall) Semantics() Semantics { return fw.cfg.Semantics }

// Location returns the device time zone.
func (fw *Firewall) Location() *time.Location { return fw.loc }

// Config returns a deep copy of the declarative configuration.
func (fw *Firewall) Config() *Config { return fw.cfg.Clone() }

// Issues returns every construct that cannot be evaluated exactly, in
// declaration order.
func (fw *Firewall) Issues() []Issue { return slices.Clone(fw.issues) }

// Rules returns the security rules in evaluation order.
func (fw *Firewall) Rules() []*Rule { return slices.Clone(fw.rules) }

// Rule returns the security rule with the given device ID.
func (fw *Firewall) Rule(id string) (*Rule, bool) {
	i := slices.IndexFunc(fw.rules, func(r *Rule) bool { return r.spec.ID == id })
	if i < 0 {
		return nil, false
	}
	return fw.rules[i], true
}

// NATRules returns the dynamic NAT rules of one kind in evaluation order.
func (fw *Firewall) NATRules(kind NATKind) []*NATRule {
	var out []*NATRule
	for _, n := range fw.nat {
		if n.spec.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

// StaticNATs returns the static NAT mappings in declaration order.
func (fw *Firewall) StaticNATs() []*StaticMapping { return slices.Clone(fw.statics) }

// Zone returns the zone with the given name.
func (fw *Firewall) Zone(name string) (Zone, bool) {
	z, ok := fw.zones[name]
	return z, ok
}

// Interface returns the interface with the given name.
func (fw *Firewall) Interface(name string) (Interface, bool) {
	i, ok := fw.interfaces[name]
	return i, ok
}

// RoutingTable returns the table of a virtual router.
func (fw *Firewall) RoutingTable(vr string) (*RoutingTable, bool) {
	t, ok := fw.tables[vr]
	return t, ok
}

// VirtualRouters returns the names of every routing table, sorted.
func (fw *Firewall) VirtualRouters() []string { return slices.Sorted(maps.Keys(fw.tables)) }

// Address returns the exact set of an address object or group. It reports
// false for unknown names and for objects that cannot be resolved exactly.
func (fw *Firewall) Address(name string) (traffic.AddressSet, bool) {
	r, ok := fw.addresses[name]
	return r.set, ok && r.exact()
}

// Service returns the exact set of a service object or group.
func (fw *Firewall) Service(name string) (traffic.ServiceSet, bool) {
	r, ok := fw.services[name]
	return r.set, ok && r.exact()
}

// Addresses yields every exactly resolvable address object and group with
// its set, ordered by name.
func (fw *Firewall) Addresses() iter.Seq2[string, traffic.AddressSet] {
	return exactObjects(fw.addresses)
}

// Services yields every exactly resolvable service object and group with
// its set, ordered by name.
func (fw *Firewall) Services() iter.Seq2[string, traffic.ServiceSet] {
	return exactObjects(fw.services)
}

func (fw *Firewall) indexNetwork() {
	for _, z := range fw.cfg.Zones {
		if _, dup := fw.zones[z.Name]; dup {
			fw.issue("zone "+z.Name, "declared more than once")
		}
		fw.zones[z.Name] = z
	}
	for _, i := range fw.cfg.Interfaces {
		if i.Zone != "" {
			if _, ok := fw.zones[i.Zone]; !ok {
				fw.issue("interface "+i.Name, "unknown zone "+quote(i.Zone))
			}
		}
		fw.interfaces[i.Name] = i
	}
}

func (fw *Firewall) compileObjects(res *resolver) {
	fw.addresses = make(map[string]resolved[traffic.AddressSet], len(res.addresses)+len(res.addressGroups))
	for _, a := range fw.cfg.Addresses {
		fw.addresses[a.Name] = res.address(a.Name)
	}
	for _, g := range fw.cfg.AddressGroups {
		if _, dup := res.addresses[g.Name]; dup {
			fw.issue("address group "+g.Name, "name also used by an address object")
		}
		fw.addresses[g.Name] = res.address(g.Name)
	}
	fw.services = make(map[string]resolved[traffic.ServiceSet], len(res.services)+len(res.serviceGroups))
	for _, s := range fw.cfg.Services {
		fw.services[s.Name] = res.service(s.Name)
	}
	for _, g := range fw.cfg.ServiceGroups {
		fw.services[g.Name] = res.service(g.Name)
	}
}

func (fw *Firewall) compileRules(res *resolver) {
	schedules := make(map[string]*Schedule, len(fw.cfg.Schedules))
	for i := range fw.cfg.Schedules {
		schedules[fw.cfg.Schedules[i].Name] = &fw.cfg.Schedules[i]
	}
	fw.rules = make([]*Rule, len(fw.cfg.Rules))
	for i, spec := range fw.cfg.Rules {
		r := &Rule{position: i, spec: spec, loc: fw.loc}
		src, dst := res.operands(spec.Source), res.operands(spec.Destination)
		svc := res.serviceList(spec.Services)
		r.issues = slices.Concat(src.problems, dst.problems, svc.problems, spec.Unsupported)
		if spec.NegateSource {
			src.set = traffic.AnyAddress().Subtract(src.set)
		}
		if spec.NegateDestination {
			dst.set = traffic.AnyAddress().Subtract(dst.set)
		}
		r.match = traffic.Space{Src: src.set, Dst: dst.set, Service: svc.set}
		r.issues = append(r.issues, fw.ruleSemanticIssues(spec)...)
		if spec.Schedule != "" {
			r.schedule = schedules[spec.Schedule]
			if r.schedule == nil {
				r.issues = append(r.issues, "unknown schedule "+quote(spec.Schedule))
			}
		}
		for _, z := range slices.Concat(spec.From, spec.To) {
			if _, ok := fw.zones[z]; !ok {
				r.issues = append(r.issues, "unknown zone "+quote(z))
			}
		}
		r.issues = slices.Compact(r.issues)
		for _, reason := range r.issues {
			fw.issue("rule "+spec.ID, reason)
		}
		fw.rules[i] = r
	}
}

func (fw *Firewall) ruleSemanticIssues(spec SecurityRule) []string {
	var out []string
	if spec.Action != ActionPermit && spec.Action != ActionDeny {
		out = append(out, "unknown action")
	}
	if len(spec.Applications) > 0 {
		out = append(out, "application match "+strings.Join(spec.Applications, ","))
	}
	if spec.ApplicationDefault {
		out = append(out, "application-default service")
	}
	return out
}

func (fw *Firewall) compileNAT(res *resolver) {
	positions := map[NATKind]int{}
	for _, spec := range fw.cfg.DynamicNATs {
		n := &NATRule{position: positions[spec.Kind], spec: spec}
		positions[spec.Kind]++
		src, dst := res.operands(spec.Source), res.operands(spec.Destination)
		svc := res.serviceList(spec.Services)
		n.match = traffic.Space{Src: src.set, Dst: dst.set, Service: svc.set}
		n.issues = slices.Concat(src.problems, dst.problems, svc.problems)
		n.translated, n.issues = fw.translation(res, spec.Translated, n.issues)
		if spec.Kind != NATKindSource && spec.Kind != NATKindDestination {
			n.issues = append(n.issues, "unknown NAT kind")
		}
		for _, reason := range n.issues {
			fw.issue("nat "+spec.ID, reason)
		}
		fw.nat = append(fw.nat, n)
	}
	for _, spec := range fw.cfg.StaticNATs {
		inside, outside := res.operands([]AddressRef{spec.Real}), res.operands([]AddressRef{spec.Mapped})
		m := &StaticMapping{spec: spec, real: inside.set, mapped: outside.set, issues: slices.Concat(inside.problems, outside.problems)}
		if m.Decidable() && !sameSize(m.real, m.mapped) {
			m.issues = append(m.issues, "real and mapped addresses differ in size or are not contiguous")
		}
		for _, reason := range m.issues {
			fw.issue("static nat "+spec.ID, reason)
		}
		fw.statics = append(fw.statics, m)
	}
}

func (fw *Firewall) translation(res *resolver, t Translation, issues []string) (traffic.AddressSet, []string) {
	switch t.Mode {
	case TranslationModeNone:
		return traffic.AddressSet{}, issues
	case TranslationModeAddress:
		r := res.operands(t.Addresses)
		return r.set, append(issues, r.problems...)
	case TranslationModeInterface:
		var out traffic.AddressSet
		for _, p := range fw.interfaces[t.Interface].Addresses {
			out = out.Union(traffic.NewAddressSet(netip.PrefixFrom(p.Addr(), p.Addr().BitLen())))
		}
		if out.IsEmpty() {
			issues = append(issues, "interface "+quote(t.Interface)+" has no address")
		}
		return out, issues
	case TranslationModeUnset:
		return traffic.AddressSet{}, append(issues, "translation mode unset")
	default:
		return traffic.AddressSet{}, append(issues, "unknown translation mode")
	}
}

func (fw *Firewall) issue(object, reason string) {
	fw.issues = append(fw.issues, Issue{Object: object, Reason: reason})
}

func exactObjects[T any](objects map[string]resolved[T]) iter.Seq2[string, T] {
	return func(yield func(string, T) bool) {
		for _, name := range slices.Sorted(maps.Keys(objects)) {
			if r := objects[name]; r.exact() && !yield(name, r.set) {
				return
			}
		}
	}
}
