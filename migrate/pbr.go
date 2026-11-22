package migrate

import (
	"net/netip"
	"slices"
	"strconv"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// policyRoutes translates policy-based routing. Targets differ in how
// entries meet their bindings: on PAN-OS every forwarding rule owns its
// ingress zones or interfaces (Capabilities.PerRulePolicyRouteID); on
// StoneOS one ordered policy is bound to each ingress. Each source entry
// keeps its place in the order of every ingress it applies to.
func (tr *translator) policyRoutes() {
	if len(tr.src.PolicyRoutes) == 0 {
		return
	}
	if tr.caps.PerRulePolicyRouteID != "" {
		tr.perRulePolicyRoutes()
		return
	}
	tr.perIngressPolicyRoutes()
}

// pbrSource names one source entry in items.
func pbrSource(r firemon.PolicyRoute) string { return r.Policy + "/" + r.ID }

// pbrEntry translates the match and forwarding of one entry; the policy,
// ID and bindings are the caller's.
func (tr *translator) pbrEntry(r firemon.PolicyRoute) (firemon.PolicyRoute, ruleResult) {
	res := ruleResult{fidelity: FidelityExact}
	out := firemon.PolicyRoute{VirtualRouter: tr.vr(r.VirtualRouter), NextHop: r.NextHop, Disabled: r.Disabled}
	if len(r.Conditions) > 0 {
		res.untranslatable("criteria beyond addresses and services (users, applications, tracking) are not translated")
	}
	if (r.NegateSource || r.NegateDestination) && !tr.caps.NegateAddresses {
		res.untranslatable("the target cannot negate policy route addresses")
	}
	out.NegateSource, out.NegateDestination = r.NegateSource, r.NegateDestination
	id := r.Policy + "_" + r.ID
	out.Source = tr.operands(&res, r.Source, false, nil, "source", id)
	out.Destination = tr.operands(&res, r.Destination, false, nil, "destination", id)
	for _, s := range r.Services {
		if set, known := tr.fw.Service(s); known && set.IsAny() {
			out.Services = nil
			break
		}
		name, why, ok := tr.serviceName(s)
		switch {
		case !ok:
			res.untranslatable("service " + s + ": " + why)
		case why != "":
			res.approximate(why)
			out.Services = append(out.Services, name)
		default:
			out.Services = append(out.Services, name)
		}
	}
	tr.pbrForwarding(&res, &out, r)
	return out, res
}

// pbrForwarding sets where the entry forwards. PAN-OS forwards through an
// egress interface, found from the next hop when the source names none;
// StoneOS forwards to a next hop and reaches it by its routes.
func (tr *translator) pbrForwarding(res *ruleResult, out *firemon.PolicyRoute, r firemon.PolicyRoute) {
	if tr.caps.PerRulePolicyRouteID == "" {
		if !r.NextHop.IsValid() {
			res.untranslatable("the target forwards policy routes to a next hop; the source names only an egress interface")
		}
		return
	}
	if r.Interface != "" {
		out.Interface = tr.iface(r.Interface)
		return
	}
	for _, i := range tr.out.Interfaces {
		if slices.ContainsFunc(i.Addresses, func(p netip.Prefix) bool { return r.NextHop.IsValid() && p.Contains(r.NextHop) }) {
			out.Interface = i.Name
			return
		}
	}
	res.untranslatable("no target interface is connected to the next hop " + r.NextHop.String())
}

// perRulePolicyRoutes writes one forwarding rule per source entry, bound
// to the ingresses of its source policy.
func (tr *translator) perRulePolicyRoutes() {
	created := map[string][]string{} // source policy -> target rules
	for _, r := range tr.src.PolicyRoutes {
		out, res := tr.pbrEntry(r)
		if res.fidelity == FidelityUntranslatable {
			tr.item(ItemKindPolicyRoute, pbrSource(r), res.fidelity, joinNotes(res.notes))
			continue
		}
		name := r.Policy
		if tr.entries(r.Policy) > 1 {
			name += "-" + r.ID
		}
		out.Policy, out.ID = tr.names.fresh(nsPolicyRoute, name), tr.caps.PerRulePolicyRouteID
		tr.out.PolicyRoutes = append(tr.out.PolicyRoutes, out)
		tr.changes.pbr = append(tr.changes.pbr, design.AddPolicyRoute{Route: out})
		for _, b := range tr.src.PolicyBindings {
			if b.Policy != r.Policy {
				continue
			}
			tb := tr.binding(b, out.Policy)
			tr.out.PolicyBindings = append(tr.out.PolicyBindings, tb)
			tr.changes.pbr = append(tr.changes.pbr, design.AddPolicyBinding{Binding: tb})
		}
		created[r.Policy] = append(created[r.Policy], out.Policy)
		tr.item(ItemKindPolicyRoute, pbrSource(r), res.fidelity, joinNotes(res.notes), out.Policy)
	}
	for _, b := range tr.src.PolicyBindings {
		tr.bindingItem(b, created[b.Policy])
	}
}

// ingress is one zone or interface that policy routes are bound to.
type ingress struct{ zone, iface string }

func (i ingress) String() string { return i.zone + i.iface }

// perIngressPolicyRoutes writes one ordered policy per ingress, with every
// source entry bound to it in source order.
func (tr *translator) perIngressPolicyRoutes() {
	var ingresses []ingress
	policies := map[ingress][]string{}
	for _, b := range tr.src.PolicyBindings {
		in := ingress{zone: b.Zone, iface: b.Interface}
		if !slices.Contains(ingresses, in) {
			ingresses = append(ingresses, in)
		}
		if !slices.Contains(policies[in], b.Policy) {
			policies[in] = append(policies[in], b.Policy)
		}
	}
	type entry struct {
		res     ruleResult
		targets []string
	}
	entries := make([]entry, len(tr.src.PolicyRoutes))
	created := map[string][]string{}
	for _, in := range ingresses {
		name := "pbr-" + in.String()
		if len(policies[in]) == 1 {
			name = policies[in][0]
		}
		policy, n := tr.names.fresh(nsPolicyRoute, name), 0
		for i, r := range tr.src.PolicyRoutes {
			if !slices.Contains(policies[in], r.Policy) {
				continue
			}
			out, res := tr.pbrEntry(r)
			entries[i].res = res
			if res.fidelity == FidelityUntranslatable {
				continue
			}
			n++
			out.Policy, out.ID = policy, strconv.Itoa(n)
			tr.out.PolicyRoutes = append(tr.out.PolicyRoutes, out)
			tr.changes.pbr = append(tr.changes.pbr, design.AddPolicyRoute{Route: out})
			entries[i].targets = append(entries[i].targets, policy+"/"+out.ID)
		}
		if n == 0 {
			continue
		}
		tb := tr.binding(firemon.PolicyBinding{Zone: in.zone, Interface: in.iface}, policy)
		tr.out.PolicyBindings = append(tr.out.PolicyBindings, tb)
		tr.changes.pbr = append(tr.changes.pbr, design.AddPolicyBinding{Binding: tb})
		for _, p := range policies[in] {
			created[p] = append(created[p], policy)
		}
	}
	for i, r := range tr.src.PolicyRoutes {
		e := entries[i]
		switch {
		case e.res.fidelity == FidelityUntranslatable:
			tr.item(ItemKindPolicyRoute, pbrSource(r), e.res.fidelity, joinNotes(e.res.notes))
		case len(e.targets) == 0:
			tr.item(ItemKindPolicyRoute, pbrSource(r), FidelityApproximate, "the policy is bound to no zone or interface: it routes nothing and is not written")
		default:
			tr.item(ItemKindPolicyRoute, pbrSource(r), e.res.fidelity, joinNotes(e.res.notes), e.targets...)
		}
	}
	for _, b := range tr.src.PolicyBindings {
		tr.bindingItem(b, created[b.Policy])
	}
}

// entries counts the entries of a source policy.
func (tr *translator) entries(policy string) int {
	n := 0
	for _, r := range tr.src.PolicyRoutes {
		if r.Policy == policy {
			n++
		}
	}
	return n
}

// binding maps a source binding's ingress onto the target policy.
func (tr *translator) binding(b firemon.PolicyBinding, policy string) firemon.PolicyBinding {
	out := firemon.PolicyBinding{Policy: policy}
	if b.Zone != "" {
		out.Zone = tr.zone(b.Zone)
	} else {
		out.Interface = tr.iface(b.Interface)
	}
	return out
}

func (tr *translator) bindingItem(b firemon.PolicyBinding, policies []string) {
	src := b.Policy + "@" + b.Zone + b.Interface
	if len(policies) == 0 {
		tr.item(ItemKindPolicyBinding, src, FidelityUntranslatable, "none of the policy's entries could be translated")
		return
	}
	at := tr.zone(b.Zone)
	if b.Zone == "" {
		at = tr.iface(b.Interface)
	}
	targets := make([]string, len(policies))
	for i, p := range policies {
		targets[i] = p + "@" + at
	}
	tr.item(ItemKindPolicyBinding, src, FidelityExact, "", targets...)
}
