package firemon

import (
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
	NextHop       netip.Addr   `json:"next_hop,omitzero"`
	Interface     string       `json:"interface,omitempty"`
	Disabled      bool         `json:"disabled,omitempty"`
	// Unsupported lists match criteria that cannot be evaluated offline,
	// such as user groups.
	Unsupported []string `json:"unsupported,omitempty"`
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
	iface      string
	zone       string
	issues     []string
	domainOnly int
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

// Egress returns the interface and zone the entry forwards to; empty when
// the next hop is unreachable.
func (p *PBRRule) Egress() (iface, zone string) { return p.iface, p.zone }

// Issues returns why the match is not exact.
func (p *PBRRule) Issues() []string { return slices.Clone(p.issues) }

// DecidableFor reports whether the match is exact, ignoring destination
// domains when the target names its domain.
func (p *PBRRule) DecidableFor(domains bool) bool {
	n := len(p.issues)
	if domains {
		n -= p.domainOnly
	}
	return n == 0
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
		src, dst := res.operands(spec.Source), res.operands(spec.Destination)
		svc := res.serviceList(spec.Services)
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
		p.issues = slices.Concat(src.allProblems(), dst.problems, svc.allProblems(), spec.Unsupported)
		p.domainOnly = len(dst.domainProblems)
		p.issues = append(p.issues, dst.domainProblems...)
		p.iface = spec.Interface
		if p.iface == "" && spec.NextHop.IsValid() {
			if t, ok := fw.tables[spec.VirtualRouter]; ok {
				p.iface = t.resolve(spec.NextHop)
			}
		}
		p.zone = fw.interfaces[p.iface].Zone
		if p.iface == "" {
			p.issues = append(p.issues, "next hop "+spec.NextHop.String()+" unreachable")
		}
		for _, reason := range p.issues {
			fw.issue("policy route "+spec.Policy+"/"+spec.ID, reason)
		}
		fw.pbr = append(fw.pbr, p)
	}
}
