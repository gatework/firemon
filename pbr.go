package firemon

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/gatework/firemon/traffic"
)

// PolicyRoute is one ordered entry of a policy-based routing policy
// (Hillstone pbr-policy match, PAN-OS PBF). Traffic entering a zone or
// interface the policy is bound to is forwarded to NextHop (or out of
// Interface) by the first entry it matches, before the routing table is
// consulted. Empty lists mean "any".
type PolicyRoute struct {
	Policy        string       `json:"policy"`
	ID            string       `json:"id"`
	VirtualRouter string       `json:"virtual_router,omitempty"`
	Source        []AddressRef `json:"source,omitempty"`
	Destination   []AddressRef `json:"destination,omitempty"`
	Services      []string     `json:"services,omitempty"`
	// NegateSource and NegateDestination invert the address match (PAN-OS).
	NegateSource      bool       `json:"negate_source,omitempty"`
	NegateDestination bool       `json:"negate_destination,omitempty"`
	NextHop           netip.Addr `json:"next_hop,omitzero"`
	Interface         string     `json:"interface,omitempty"`
	Disabled          bool       `json:"disabled,omitempty"`
	// Conditions are criteria beyond addresses and services, such as user
	// groups; they cannot be evaluated offline.
	Conditions []Condition `json:"conditions,omitempty"`
}

// PolicyBinding attaches a policy-based routing policy to the traffic
// entering a zone or an interface.
type PolicyBinding struct {
	Policy    string `json:"policy"`
	Zone      string `json:"zone,omitempty"`
	Interface string `json:"interface,omitempty"`
}

// PBRRule is a compiled policy route.
type PBRRule struct {
	position   int
	spec       PolicyRoute
	match      traffic.Space
	bound      traffic.Space
	dstDomains traffic.DomainSet
	egresses   []Egress
	issues     []Issue
}

// Position returns the zero-based position in the policy routes of the
// configuration.
func (p *PBRRule) Position() int { return p.position }

// Spec returns the declarative entry. Its slices are shared and read-only.
func (p *PBRRule) Spec() PolicyRoute { return p.spec }

// Match returns the exact match space.
func (p *PBRRule) Match() traffic.Space { return p.match }

// Bound returns a space containing every packet the entry can match.
func (p *PBRRule) Bound() traffic.Space { return p.bound }

// DstDomains returns the destination domain patterns of the entry.
func (p *PBRRule) DstDomains() traffic.DomainSet { return p.dstDomains }

// Egress returns the interface and zone when the policy route has one physical exit.
func (p *PBRRule) Egress() (iface, zone string) {
	if len(p.egresses) == 1 {
		return p.egresses[0].Interface, p.egresses[0].Zone
	}
	return "", ""
}

// Egresses returns all physical exits for the policy route's next hop.
func (p *PBRRule) Egresses() []Egress { return slices.Clone(p.egresses) }

// Issues returns why the match is not exact.
func (p *PBRRule) Issues() []Issue { return slices.Clone(p.issues) }

// DecidableFor reports whether the match is exact, ignoring destination
// domains when the target names its domain.
func (p *PBRRule) DecidableFor(domains bool) bool {
	for _, is := range p.issues {
		if !domains || is.Kind != IssueKindDestinationDomain {
			return false
		}
	}
	return true
}

// PolicyRoutesFor returns the enabled policy routes that apply to traffic
// entering zone or interface iface, in evaluation order.
func (fw *Firewall) PolicyRoutesFor(zone, iface string) []*PBRRule {
	var policies []string
	for _, b := range fw.cfg.PolicyBindings {
		if (b.Zone != "" && b.Zone == zone) || (b.Interface != "" && b.Interface == iface) {
			policies = append(policies, b.Policy)
		}
	}
	var out []*PBRRule
	for _, p := range fw.pbr {
		if slices.Contains(policies, p.spec.Policy) && !p.spec.Disabled {
			out = append(out, p)
		}
	}
	return out
}

func (fw *Firewall) compilePolicyRoutes(res *resolver) {
	for i, spec := range fw.cfg.PolicyRoutes {
		p := &PBRRule{position: i, spec: spec}
		p.compileMatch(res)
		p.egresses = fw.policyEgresses(spec)
		if len(p.egresses) == 0 {
			p.issues = append(p.issues, Issue{Kind: IssueKindConfig, Reason: "next hop " + spec.NextHop.String() + " unreachable"})
		}
		for _, is := range p.issues {
			fw.issues = append(fw.issues, Issue{Kind: is.Kind, Object: "policy route " + spec.Policy + "/" + spec.ID, Reason: is.Reason})
		}
		fw.pbr = append(fw.pbr, p)
	}
}

// compileMatch resolves the entry's match, its bound when operands are
// not exact, and the issues that make it undecidable.
func (p *PBRRule) compileMatch(res *resolver) {
	spec := p.spec
	src, dst := res.operands(spec.Source), res.operands(spec.Destination)
	svc := res.serviceList(spec.Services)
	if spec.NegateSource && src.exact() {
		src.set = traffic.AnyAddress().Subtract(src.set)
	}
	if spec.NegateDestination && dst.exact() {
		dst.set = traffic.AnyAddress().Subtract(dst.set)
	}
	p.match = traffic.Space{Src: src.set, Dst: dst.set, Service: svc.set}
	p.bound = p.match
	if !src.exact() {
		p.bound.Src = traffic.AnyAddress()
	}
	if !dst.exact() {
		p.bound.Dst = traffic.AnyAddress()
	}
	if !svc.exact() {
		p.bound.Service = traffic.AnyService()
	}
	p.dstDomains = dst.domains
	p.issues = slices.Concat(
		issuesOf(IssueKindObject, src.problems), issuesOf(IssueKindDomain, src.domainProblems),
		issuesOf(IssueKindObject, dst.problems), issuesOf(IssueKindDestinationDomain, dst.domainProblems),
		issuesOf(IssueKindObject, svc.problems), criteriaIssues(spec.Conditions))
	if (spec.NegateSource && !src.exact()) || (spec.NegateDestination && !dst.exact()) {
		p.issues = append(p.issues, Issue{Kind: IssueKindObject, Reason: "negated operand is not exact"})
	}
}

// policyEgresses is where an entry forwards: its egress interface, or the
// routes to its next hop.
func (fw *Firewall) policyEgresses(spec PolicyRoute) []Egress {
	switch {
	case spec.Interface != "":
		ifc := fw.interfaces[spec.Interface]
		return []Egress{{Interface: spec.Interface, Zone: ifc.Zone, NextHop: spec.NextHop, Route: Route{VirtualRouter: spec.VirtualRouter}}}
	case spec.NextHop.IsValid():
		vr := cmp.Or(spec.VirtualRouter, fw.Semantics().DefaultVirtualRouter)
		egresses, _ := fw.Forward(vr, traffic.AddressRange(spec.NextHop, spec.NextHop))
		for j := range egresses {
			if !egresses[j].NextHop.IsValid() {
				egresses[j].NextHop = spec.NextHop
			}
		}
		return egresses
	}
	return nil
}
