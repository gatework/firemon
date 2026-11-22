package inventory

import (
	"slices"

	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

// Upstream records that a crossing evaluates traffic as an earlier
// firewall's NAT leaves it: the operator's flow (Original) arrives as
// Translated.
type Upstream struct {
	Cluster    string
	Original   traffic.Space
	Translated traffic.Space
}

// maxChainHops bounds the NAT hand-offs one trace follows.
const maxChainHops = 64

// followNAT hands translated traffic to the firewalls that receive it.
// A crossing whose NAT rewrites addresses or ports sends the packet, as it
// leaves, to the next firewall its routes reach. That firewall evaluates
// the translated packet instead of the original one, and a firewall the
// original addresses never reached joins the trace. Traffic without NAT
// is left as the per-firewall evaluation found it.
func (inv *Inventory) followNAT(t *Trace, work map[string]*assignment, req query.Request) error {
	handed := map[string]bool{}
	for i := 0; i < len(t.Crossings) && len(handed) < maxChainHops; i++ {
		c := t.Crossings[i]
		m := inv.primary(c.Cluster)
		for _, p := range c.Paths {
			if !p.NATChanges() {
				continue
			}
			out := p.Leaving()
			for _, next := range inv.nextHops(m, out.Dst, req.VirtualRouter) {
				key := c.Cluster + ">" + next + ":" + p.Original.String()
				if handed[key] || next == c.Cluster {
					continue
				}
				handed[key] = true
				up := Upstream{Cluster: c.Cluster, Original: p.Original, Translated: out}
				if err := inv.handOff(t, work, next, up, req); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// handOff re-evaluates cluster with up's original traffic replaced by its
// translation.
func (inv *Inventory) handOff(t *Trace, work map[string]*assignment, cluster string, up Upstream, req query.Request) error {
	old := work[cluster]
	a := &assignment{ownership: OwnershipTransit}
	if old != nil {
		a.ownership, a.basis = old.ownership, slices.Clone(old.basis)
		for _, q := range old.parts {
			a.parts = append(a.parts, subtractBox(q, up.Original)...)
		}
	}
	for _, zs := range inv.zonesOf(cluster, up.Translated.Src) {
		for _, zd := range inv.zonesOf(cluster, up.Translated.Dst) {
			a.parts = append(a.parts, Part{Src: zs.set, Dst: zd.set, Service: up.Translated.Service, FromZone: zs.zone, ToZone: zd.zone})
		}
	}
	work[cluster] = a
	c, err := inv.evaluate(cluster, a, req)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(t.Crossings, func(x Crossing) bool { return x.Cluster == cluster })
	if i >= 0 {
		c.Upstream = append(slices.Clone(t.Crossings[i].Upstream), up)
		t.Crossings[i] = c
		return nil
	}
	if len(c.Paths) > 0 {
		c.Upstream = []Upstream{up}
		t.Crossings = append(t.Crossings, c)
	}
	return nil
}

// subtractBox removes the box s (sources by destinations) from a part:
// what is left is at most two parts.
func subtractBox(p Part, s traffic.Space) []Part {
	if !p.Src.Overlaps(s.Src) || !p.Dst.Overlaps(s.Dst) {
		return []Part{p}
	}
	var out []Part
	if rest := p.Src.Subtract(s.Src); !rest.IsEmpty() {
		q := p
		q.Src = rest
		out = append(out, q)
	}
	if rest := p.Dst.Subtract(s.Dst); !rest.IsEmpty() {
		q := p
		q.Src, q.Dst = p.Src.Intersect(s.Src), rest
		out = append(out, q)
	}
	return out
}

// sequence numbers the crossings in the order traffic meets them: along
// route next hops, starting from the firewalls nothing in the trace hands
// traffic to (those owning the sources). Firewalls on a cycle or not
// connected keep their trace order after the others.
func (inv *Inventory) sequence(t *Trace, vr string) {
	n := len(t.Crossings)
	index := map[string]int{}
	for i, c := range t.Crossings {
		index[c.Cluster] = i
	}
	next := make([][]int, n)
	incoming := make([]int, n)
	for i, c := range t.Crossings {
		dst := c.Dst
		for _, p := range c.Paths {
			dst = dst.Union(p.Leaving().Dst)
		}
		for _, cl := range inv.nextHops(inv.primary(c.Cluster), dst, vr) {
			if j, ok := index[cl]; ok && j != i && !slices.Contains(next[i], j) {
				next[i] = append(next[i], j)
				incoming[j]++
			}
		}
	}
	seq := 0
	done := make([]bool, n)
	var ready []int
	for i := range n {
		if incoming[i] == 0 {
			ready = append(ready, i)
		}
	}
	for len(ready) > 0 {
		i := ready[0]
		ready = ready[1:]
		done[i] = true
		seq++
		t.Crossings[i].Seq = seq
		for _, j := range next[i] {
			if incoming[j]--; incoming[j] == 0 {
				ready = append(ready, j)
			}
		}
	}
	for i := range n {
		if !done[i] {
			seq++
			t.Crossings[i].Seq = seq
		}
	}
}
