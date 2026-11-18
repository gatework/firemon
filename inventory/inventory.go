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
}

// Protection declares networks a firewall protects, optionally behind one
// of its zones (the protected networks of an operator inventory).
type Protection struct {
	Firewall string
	Zone     string
	Networks []netip.Prefix
	Exclude  []netip.Prefix
}

// Options configures an Inventory. The zero value evaluates at time.Now
// and derives every ownership from routing.
type Options struct {
	Now func() time.Time
	// Protections are the declared protected networks; members of clusters
	// without any are owned by routing instead.
	Protections []Protection
}

// Inventory is an immutable set of firewalls, safe for concurrent use.
type Inventory struct {
	members   []member
	claims    []claim
	byAddress map[netip.Addr][]string // interface address -> clusters
	now       func() time.Time
}

type member struct {
	name, cluster string
	fw            *firemon.Firewall
	engine        *query.Engine
	planner       *design.Planner
}

// New returns an inventory of members. Members are ordered by name;
// protections must name known members.
func New(members []Member, opts Options) (*Inventory, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	inv := &Inventory{now: now, byAddress: map[netip.Addr][]string{}}
	for _, m := range members {
		if slices.ContainsFunc(inv.members, func(x member) bool { return x.name == m.Name }) {
			return nil, fmt.Errorf("%w: %q", ErrDuplicate, m.Name)
		}
		inv.members = append(inv.members, member{
			name: m.Name, cluster: cmp.Or(m.Cluster, m.Name), fw: m.Firewall,
			engine:  query.New(m.Firewall, query.Options{Now: now}),
			planner: design.New(m.Firewall, design.Options{Now: now, Naming: m.Naming}),
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
	claims, err := inv.buildClaims(opts.Protections)
	if err != nil {
		return nil, err
	}
	inv.claims = claims
	return inv, nil
}

// primary returns the member a cluster is evaluated on.
func (inv *Inventory) primary(cluster string) *member {
	i := slices.IndexFunc(inv.members, func(m member) bool { return m.cluster == cluster })
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
