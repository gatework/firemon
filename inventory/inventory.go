package inventory

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/query"
)

// ErrUnsupported reports an inventory feature locating does not honour
// yet, rejected rather than ignored.
var ErrUnsupported = errors.New("inventory: not supported yet")

// ErrDuplicate reports two members with the same name.
var ErrDuplicate = errors.New("inventory: duplicate firewall name")

// Member is one firewall of the inventory.
type Member struct {
	Name string
	// Cluster groups HA members that share configuration; empty means the
	// member is its own cluster. A cluster is evaluated and planned once,
	// on its first member by name.
	Cluster  string
	Firewall *firemon.Firewall
	// Naming is the vendor naming policy for planned objects.
	Naming design.Naming
	// Active marks the cluster member evaluated and planned on; without
	// one, the first member by name is.
	Active bool
	// Host is the management address, for naming the device to operators.
	Host string
	// Capabilities are what the vendor's rules express (validity windows,
	// inline entries), for the planner.
	Capabilities firemon.Capabilities
}

// Protection declares networks a firewall protects, optionally behind one
// of its zones (the protected networks of an operator inventory).
type Protection struct {
	Firewall string
	// VirtualRouter would restrict the protection to one routing context;
	// New rejects it until locating honours routing contexts.
	VirtualRouter string
	Zone          string
	Networks      []netip.Prefix
	Exclude       []netip.Prefix
}

// ZoneBinding binds networks to a zone of a firewall. Protected bindings
// are the networks the firewall protects: a request whose source or
// destination falls in them crosses it. Every binding, protected or not,
// tells which zone an address is in on that firewall, for example
// untrust = 0.0.0.0/0.
type ZoneBinding struct {
	Firewall string
	// VirtualRouter would restrict the binding to one routing context; New
	// rejects it until locating honours routing contexts.
	VirtualRouter string
	Zone          string
	Networks      []netip.Prefix
	Exclude       []netip.Prefix
	Protected     bool
}

// Options configures an Inventory. The zero value evaluates at time.Now
// and derives every ownership from routing.
type Options struct {
	Now func() time.Time
	// Protections are the declared protected networks; members of clusters
	// without any are owned by routing instead.
	Protections []Protection
	// Zones bind networks to zones; the protected ones are protections.
	Zones []ZoneBinding
}

// Inventory is an immutable set of firewalls, safe for concurrent use.
type Inventory struct {
	members []member
	claims  []claim
	// bindings are each cluster's zone bindings, longest prefix first.
	bindings  map[string][]binding
	byAddress map[netip.Addr][]string // interface address -> clusters
	now       func() time.Time
	// opts and given are what New was called with, for Applied.
	opts  Options
	given []Member
}

type member struct {
	name, cluster string
	host          string
	caps          firemon.Capabilities
	active        bool
	fw            *firemon.Firewall
	engine        *query.Engine
	planner       *design.Planner
	naming        design.Naming
}

// New returns an inventory of members. Members are ordered by name;
// protections must name known members.
func New(members []Member, opts Options) (*Inventory, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	for _, p := range opts.Protections {
		if p.VirtualRouter != "" {
			return nil, fmt.Errorf("%w: %s: protected networks per virtual router (%s)", ErrUnsupported, p.Firewall, p.VirtualRouter)
		}
	}
	for _, z := range opts.Zones {
		if z.VirtualRouter != "" {
			return nil, fmt.Errorf("%w: %s: zone %s bound per virtual router (%s)", ErrUnsupported, z.Firewall, z.Zone, z.VirtualRouter)
		}
	}
	inv := &Inventory{now: now, byAddress: map[netip.Addr][]string{}, opts: opts, given: slices.Clone(members)}
	for _, m := range members {
		if slices.ContainsFunc(inv.members, func(x member) bool { return x.name == m.Name }) {
			return nil, fmt.Errorf("%w: %q", ErrDuplicate, m.Name)
		}
		inv.members = append(inv.members, member{
			name: m.Name, cluster: cmp.Or(m.Cluster, m.Name), fw: m.Firewall, active: m.Active, host: m.Host, caps: m.Capabilities,
			engine:  query.New(m.Firewall, query.Options{Now: now}),
			planner: design.New(m.Firewall, design.Options{Now: now, Naming: m.Naming, Capabilities: m.Capabilities}),
			naming:  m.Naming,
		})
	}
	slices.SortFunc(inv.members, func(a, b member) int { return cmp.Compare(a.name, b.name) })
	for _, m := range inv.members {
		for _, ifc := range m.fw.Config().Interfaces {
			for _, p := range ifc.Addresses {
				if !slices.Contains(inv.byAddress[p.Addr()], m.cluster) {
					inv.byAddress[p.Addr()] = append(inv.byAddress[p.Addr()], m.cluster)
				}
			}
		}
	}
	protections := slices.Clone(opts.Protections)
	for _, z := range opts.Zones {
		if z.Protected {
			protections = append(protections, Protection{Firewall: z.Firewall, Zone: z.Zone, Networks: z.Networks, Exclude: z.Exclude})
		}
	}
	claims, err := inv.buildClaims(protections)
	if err != nil {
		return nil, err
	}
	inv.claims = claims
	if inv.bindings, err = inv.buildBindings(protections, opts.Zones); err != nil {
		return nil, err
	}
	return inv, nil
}

// Clusters returns the cluster names in order.
func (inv *Inventory) Clusters() []string {
	var out []string
	for _, m := range inv.members {
		if !slices.Contains(out, m.cluster) {
			out = append(out, m.cluster)
		}
	}
	return out
}

// Firewall returns the firewall a cluster is evaluated on, or nil.
func (inv *Inventory) Firewall(cluster string) *firemon.Firewall {
	if m := inv.primary(cluster); m != nil {
		return m.fw
	}
	return nil
}

// Primary returns the name of the member a cluster is evaluated and
// changed on: its active member, else the first by name.
func (inv *Inventory) Primary(cluster string) string {
	if m := inv.primary(cluster); m != nil {
		return m.name
	}
	return ""
}

// Members returns the names of a cluster's members.
func (inv *Inventory) Members(cluster string) []string { return inv.clusterMembers(cluster) }

// primary returns the member a cluster is evaluated on.
func (inv *Inventory) primary(cluster string) *member {
	i := slices.IndexFunc(inv.members, func(m member) bool { return m.cluster == cluster && m.active })
	if i < 0 {
		i = slices.IndexFunc(inv.members, func(m member) bool { return m.cluster == cluster })
	}
	if i < 0 {
		return nil
	}
	return &inv.members[i]
}

func (inv *Inventory) memberNamed(name string) *member {
	i := slices.IndexFunc(inv.members, func(m member) bool { return m.name == name })
	if i < 0 {
		return nil
	}
	return &inv.members[i]
}

// clusterMembers lists the member names of a cluster.
func (inv *Inventory) clusterMembers(cluster string) []string {
	var out []string
	for _, m := range inv.members {
		if m.cluster == cluster {
			out = append(out, m.name)
		}
	}
	return out
}
