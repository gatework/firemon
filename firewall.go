package firemon

import (
	"cmp"
	"errors"
	"fmt"
	"iter"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/gatework/firemon/traffic"
)

// ErrInvalidConfig reports a configuration that cannot be compiled at all.
var ErrInvalidConfig = errors.New("firemon: invalid configuration")

// Firewall is a compiled, immutable firewall. It is safe for concurrent use.
type Firewall struct {
	cfg         *Config
	loc         *time.Location
	addresses   map[string]resolved[traffic.AddressSet]
	services    map[string]resolved[traffic.ServiceSet]
	zones       map[string]Zone
	interfaces  map[string]Interface
	tables      map[string]*RoutingTable
	rules       []*Rule
	ruleByID    map[string]*Rule // first rule of each ID
	nat         []*NATRule
	statics     []*StaticMapping
	pbr         []*PBRRule
	issues      []Issue
	fingerprint string
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
		cfg:         cfg,
		fingerprint: fingerprint(cfg),
		loc:         cmp.Or(cfg.Location, time.UTC),
		zones:       make(map[string]Zone, len(cfg.Zones)),
		interfaces:  make(map[string]Interface, len(cfg.Interfaces)),
	}
	fw.indexNetwork()
	res := newResolver(cfg)
	fw.compileObjects(res)
	fw.compileRules(res)
	fw.compileNAT(res)
	var issues []Issue
	fw.tables, issues = buildRoutingTables(cfg, fw.interfaces)
	fw.issues = append(fw.issues, issues...)
	fw.compilePolicyRoutes(res)
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
	r, ok := fw.ruleByID[id]
	return r, ok
}

// ApplicationPorts returns the default ports of an application, ignoring
// case; false when the application book does not know it.
func (fw *Firewall) ApplicationPorts(app string) (traffic.ServiceSet, bool) {
	return fw.cfg.Applications.Lookup(app)
}

// RuleGroups returns the rule groups in declaration order.
func (fw *Firewall) RuleGroups() []RuleGroup { return slices.Clone(fw.cfg.RuleGroups) }

// NATRules returns the dynamic NAT rules in declaration order.
func (fw *Firewall) NATRules() []*NATRule { return slices.Clone(fw.nat) }

// NATRulesFor returns the rules that decide one side, in order.
func (fw *Firewall) NATRulesFor(side NATKind) []*NATRule {
	var out []*NATRule
	for _, n := range fw.nat {
		if n.Translates(side) {
			out = append(out, n)
		}
	}
	return out
}

// StaticNATs returns the static NAT mappings in declaration order.
func (fw *Firewall) StaticNATs() []*StaticMapping { return slices.Clone(fw.statics) }

// Bridges reports whether an interface is bound to a layer-2 zone
// (transparent mode): traffic through it is not located by routing. The
// predefined layer-2 zones alone do not count.
func (fw *Firewall) Bridges() bool {
	for _, i := range fw.cfg.Interfaces {
		if z, ok := fw.zones[i.Zone]; ok && z.Mode == ZoneModeLayer2 {
			return true
		}
	}
	return false
}

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
		if onlyExclusions(a.Entries) {
			fw.issue("address "+a.Name, "only exclusions: read as every address except them")
		}
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
	fw.ruleByID = make(map[string]*Rule, len(fw.cfg.Rules))
	seen := make(map[string]bool, len(fw.cfg.Rules))
	for i, spec := range fw.cfg.Rules {
		if seen[spec.ID] {
			fw.issue("rule "+spec.ID, "rule ID declared more than once")
		}
		seen[spec.ID] = true
		r := &Rule{position: i, spec: spec, loc: fw.loc}
		var certain bool
		r.match, r.bound, r.issues, r.dstDomains, certain = ruleSpace(res, spec)
		apps := appIssues(spec)
		semantic := fw.ruleSemanticIssues(spec)
		r.issues = slices.Concat(r.issues, apps, semantic)
		r.certain = certain && len(apps) == 0 && len(semantic) == 0
		for _, a := range spec.Applications {
			r.apps = append(r.apps, strings.ToLower(a))
		}
		if spec.Schedule != "" {
			r.schedule = schedules[spec.Schedule]
			switch {
			case r.schedule == nil:
				r.issues, r.certain = append(r.issues, Issue{Kind: IssueKindSchedule, Reason: "unknown schedule " + quote(spec.Schedule)}), false
			case r.schedule.Unsupported != "":
				r.issues, r.certain = append(r.issues, Issue{Kind: IssueKindSchedule, Reason: "unsupported schedule " + quote(spec.Schedule)}), false
			}
		}
		for _, z := range slices.Concat(spec.From, spec.To) {
			if _, ok := fw.zones[z]; !ok {
				r.issues, r.certain = append(r.issues, Issue{Kind: IssueKindZone, Reason: "unknown zone " + quote(z)}), false
			}
		}
		r.issues = slices.Compact(r.issues)
		if spec.Incomplete != "" {
			// The device ignores the rule, so its match is exact: nothing.
			r.issues = nil
			fw.issues = append(fw.issues, Issue{Kind: IssueKindConfig, Object: "rule " + spec.ID, Reason: "incomplete, never matches: " + spec.Incomplete})
		}
		for _, is := range r.issues {
			fw.issues = append(fw.issues, Issue{Kind: is.Kind, Object: "rule " + spec.ID, Reason: is.Reason})
		}
		fw.rules[i] = r
		if _, dup := fw.ruleByID[spec.ID]; !dup {
			fw.ruleByID[spec.ID] = r
		}
	}
}

// ruleSpace resolves a rule's operands into its exact match space, an
// upper bound of what it can match, and the reasons the match is inexact.
func ruleSpace(res *resolver, spec SecurityRule) (match, bound traffic.Space, issues []Issue, dstDomains traffic.DomainSet, certain bool) {
	src, dst := res.operands(spec.Source), res.operands(spec.Destination)
	svc := res.serviceList(spec.Services)
	if len(spec.ServiceEntries) > 0 {
		if len(spec.Services) == 0 {
			svc.set = traffic.ServiceSet{}
		}
		for _, e := range spec.ServiceEntries {
			svc.set = svc.set.Union(e.Set())
		}
	}
	if spec.NegateSource {
		src.set = traffic.AnyAddress().Subtract(src.set)
	}
	if spec.NegateDestination {
		dst.set = traffic.AnyAddress().Subtract(dst.set)
	}
	match = traffic.Space{Src: src.set, Dst: dst.set, Service: svc.set}
	bound = match
	if !src.exact() {
		bound.Src = traffic.AnyAddress()
	}
	if !dst.exact() {
		bound.Dst = traffic.AnyAddress()
	}
	if !svc.exact() || spec.ApplicationDefault {
		bound.Service = traffic.AnyService()
	}
	issues = slices.Concat(
		issuesOf(IssueKindObject, src.problems), issuesOf(IssueKindDomain, src.domainProblems),
		issuesOf(IssueKindObject, dst.problems), issuesOf(IssueKindObject, svc.problems),
		unsupportedIssues(spec.Unsupported))
	// match is certainly matched when every dimension only understates the
	// true set and no other criterion narrows the rule. A negated inexact
	// dimension turns an understatement into an overstatement.
	certain = !src.overstated && !dst.overstated && !svc.overstated && len(spec.Unsupported) == 0 &&
		!spec.ApplicationDefault && (!spec.NegateSource || src.exact()) && (!spec.NegateDestination || dst.exact())
	if spec.NegateDestination && !dst.domains.IsEmpty() {
		// A negated domain cannot be matched by name either.
		return match, bound, append(issues, issuesOf(IssueKindDomain, dst.domainProblems)...), traffic.DomainSet{}, certain
	}
	return match, bound, append(issues, issuesOf(IssueKindDestinationDomain, dst.domainProblems)...), dst.domains, certain
}

// appIssues are the reasons application matching makes a rule inexact for
// targets that do not name an application.
func appIssues(spec SecurityRule) []Issue {
	var out []Issue
	if len(spec.Applications) > 0 {
		out = append(out, Issue{Kind: IssueKindApplication, Reason: "application match " + strings.Join(spec.Applications, ",")})
	}
	if spec.ApplicationDefault {
		out = append(out, Issue{Kind: IssueKindApplication, Reason: "application-default service"})
	}
	return out
}

func (fw *Firewall) ruleSemanticIssues(spec SecurityRule) []Issue {
	if spec.Action != ActionPermit && spec.Action != ActionDeny {
		return []Issue{{Kind: IssueKindAction, Reason: "unknown action"}}
	}
	return nil
}

func (fw *Firewall) compileNAT(res *resolver) {
	for i, spec := range fw.cfg.DynamicNATs {
		n := &NATRule{position: i, spec: spec}
		src, dst := res.operands(spec.Source), res.operands(spec.Destination)
		svc := res.serviceList(spec.Services)
		n.match = traffic.Space{Src: src.set, Dst: dst.set, Service: svc.set}
		n.bound = n.match
		if !src.exact() {
			n.bound.Src = traffic.AnyAddress()
		}
		if !dst.exact() {
			n.bound.Dst = traffic.AnyAddress()
		}
		if !svc.exact() {
			n.bound.Service = traffic.AnyService()
		}
		n.issues = slices.Concat(src.allProblems(), dst.allProblems(), svc.allProblems(), spec.Unsupported)
		n.src, n.issues = fw.translation(res, spec.TranslatedSource, n.issues)
		n.dst, n.issues = fw.translation(res, spec.TranslatedDestination, n.issues)
		if spec.TranslatedSource.Mode == TranslationModeUnset && spec.TranslatedDestination.Mode == TranslationModeUnset {
			n.issues = append(n.issues, "no translation")
		}
		for _, reason := range n.issues {
			fw.issue("nat "+spec.ID, reason)
		}
		fw.nat = append(fw.nat, n)
	}
	for _, spec := range fw.cfg.StaticNATs {
		inside, outside := res.operands([]AddressRef{spec.Real}), res.operands([]AddressRef{spec.Mapped})
		m := &StaticMapping{spec: spec, real: inside.set, mapped: outside.set, issues: slices.Concat(inside.allProblems(), outside.allProblems())}
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
		return r.set, append(issues, r.allProblems()...)
	case TranslationModeInterface:
		if t.Interface == "" {
			return traffic.AddressSet{}, issues // the egress interface, known only per packet
		}
		out := fw.interfaces[t.Interface].HostAddresses()
		if out.IsEmpty() {
			issues = append(issues, "interface "+quote(t.Interface)+" has no address")
		}
		return out, issues
	case TranslationModeUnset:
		return traffic.AddressSet{}, issues
	default:
		return traffic.AddressSet{}, append(issues, "unknown translation mode")
	}
}

func (fw *Firewall) issue(object, reason string) {
	fw.issues = append(fw.issues, Issue{Kind: IssueKindConfig, Object: object, Reason: reason})
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
