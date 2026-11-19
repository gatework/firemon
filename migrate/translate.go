package migrate

import (
	"cmp"
	"errors"
	"fmt"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// ErrSameVendor reports a translation to the source's own vendor.
var ErrSameVendor = errors.New("migrate: source and target are the same vendor")

// translator holds the state of one translation.
type translator struct {
	src     *firemon.Config
	fw      *firemon.Firewall // the compiled source
	t       Target
	caps    firemon.Capabilities
	m       Mapping
	names   *namer
	out     *firemon.Config
	items   []Item
	changes changeSet
	// broken names source objects (address or service namespace) the
	// target cannot express; rules that use them are disabled.
	broken map[namespace]map[string]string
	// ruleMap lists, per translated source rule, its target rules.
	ruleMap map[string][]string
	// disabledDenies are the deny rules carried over disabled.
	disabledDenies []string
}

// changeSet keeps changes by kind so the plan lists them in dependency
// order whatever order they were found in.
type changeSet struct {
	network, schedules, addresses, groups, services, svcGroups, rules, nat []design.Change
}

func (c changeSet) all() []design.Change {
	var out []design.Change
	for _, part := range [][]design.Change{c.network, c.schedules, c.addresses, c.groups, c.services, c.svcGroups, c.rules, c.nat} {
		out = append(out, part...)
	}
	return out
}

// Translate translates src into a configuration for the target.
func Translate(src *firemon.Config, m Mapping, t Target) (Result, error) {
	if src.Vendor == t.Vendor {
		return Result{}, ErrSameVendor
	}
	fw, err := firemon.Compile(src)
	if err != nil {
		return Result{}, fmt.Errorf("migrate: source: %w", err)
	}
	tr := &translator{
		src: src, fw: fw, t: t, caps: t.Capabilities, m: m, names: newNamer(t),
		out:    &firemon.Config{Vendor: t.Vendor, Semantics: t.Semantics, Location: src.Location, TimeZone: src.TimeZone, Hostname: src.Hostname},
		broken: map[namespace]map[string]string{},
	}
	for _, name := range t.Services.Names() {
		tr.names.reserve(nsService, name)
	}
	tr.network()
	tr.schedules()
	tr.addresses()
	tr.services()
	tr.rules()
	tr.defaults()
	tr.nat()
	tr.out.Services = append(tr.out.Services, t.Services.Services(func(name string) bool { return tr.declared(name) })...)
	if _, err := firemon.Compile(tr.out); err != nil {
		return Result{}, fmt.Errorf("migrate: target: %w", err)
	}
	res := Result{
		Config: tr.out,
		Plan:   &design.Plan{Kind: design.PlanKindMigration, Status: design.StatusChange, Changes: tr.changes.all()},
		Items:  tr.items,

		DisabledDenies: tr.disabledDenies,
	}
	tr.verify(&res)
	return res, nil
}

func (tr *translator) item(kind ItemKind, source string, f Fidelity, reason string, targets ...string) {
	tr.items = append(tr.items, Item{Kind: kind, Source: source, Target: targets, Fidelity: f, Reason: reason})
}

// markBroken records an object the target cannot express.
func (tr *translator) markBroken(ns namespace, name, reason string) {
	if tr.broken[ns] == nil {
		tr.broken[ns] = map[string]string{}
	}
	tr.broken[ns][name] = reason
}

func (tr *translator) declared(name string) bool {
	for _, s := range tr.out.Services {
		if s.Name == name {
			return true
		}
	}
	for _, g := range tr.out.ServiceGroups {
		if g.Name == name {
			return true
		}
	}
	return false
}

// mapped returns the mapping of name, or name itself.
func mapped(m map[string]string, name string) string { return cmp.Or(m[name], name) }
