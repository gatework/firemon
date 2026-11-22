package design

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// catalog finds existing objects equal to a needed set and creates the
// missing ones, keeping names unique.
type catalog struct {
	naming    Naming
	addresses map[string]string // canonical set -> object name
	services  map[string]string
	taken     map[string]bool
	created   []Change
	rules     int
	threshold int
}

func newCatalog(fw *firemon.Firewall, naming Naming) *catalog {
	c := &catalog{naming: naming, addresses: map[string]string{}, services: map[string]string{}, taken: map[string]bool{}, threshold: DefaultGroupThreshold}
	cfg := fw.Config()
	for _, a := range cfg.Addresses {
		c.taken[a.Name] = true
	}
	for _, g := range cfg.AddressGroups {
		c.taken[g.Name] = true
	}
	for _, s := range cfg.Services {
		c.taken[s.Name] = true
	}
	for _, g := range cfg.ServiceGroups {
		c.taken[g.Name] = true
	}
	for _, r := range cfg.Rules {
		c.taken[r.ID], c.taken[r.Name] = true, true // rule names may not collide either (PAN-OS merges)
	}
	for _, n := range cfg.DynamicNATs {
		c.taken[n.ID], c.taken[n.Name] = true, true
	}
	for name, set := range fw.Addresses() {
		if key := set.String(); c.addresses[key] == "" {
			c.addresses[key] = name
		}
	}
	for name, set := range fw.Services() {
		if key := set.String(); c.services[key] == "" {
			c.services[key] = name
		}
	}
	return c
}

// addressNames returns object names whose union is exactly s, reusing an
// object equal to s or to each of its ranges. Nil means any address.
func (c *catalog) addressNames(s traffic.AddressSet) []string {
	if s.Equal(traffic.AnyAddress()) {
		// A vendor whose rules name "any" through a predefined object
		// (StoneOS Any) gets that object, as the device writes it back;
		// elsewhere any is the empty list.
		if name, ok := c.addresses[s.String()]; ok {
			return []string{name}
		}
		return nil
	}
	if name, ok := c.addresses[s.String()]; ok {
		return []string{name}
	}
	var out []string
	for _, r := range s.Ranges() {
		piece := traffic.AddressRange(r.From(), r.To())
		if name, ok := c.addresses[piece.String()]; ok {
			out = append(out, name)
			continue
		}
		name := c.unique(c.naming.Address(r))
		entry := firemon.RangeEntry(r.From(), r.To())
		if p, ok := r.Prefix(); ok {
			entry = firemon.PrefixEntry(netip.PrefixFrom(p.Addr(), p.Bits()))
		}
		c.created = append(c.created, AddAddress{Address: firemon.Address{Name: name, Entries: []firemon.AddressEntry{entry}}})
		c.addresses[piece.String()] = name
		out = append(out, name)
	}
	return out
}

// serviceNames returns object names whose union is exactly s. Nil means any.
func (c *catalog) serviceNames(s traffic.ServiceSet) []string {
	if s.IsAny() {
		if name, ok := c.services[s.String()]; ok {
			return []string{name} // as for addresses: StoneOS Any
		}
		return nil
	}
	if name, ok := c.services[s.String()]; ok {
		return []string{name}
	}
	var out []string
	for r := range s.All() {
		piece := traffic.NewService(r.ProtocolLow, r.Src, r.Dst)
		if r.ProtocolLow != r.ProtocolHigh {
			piece, _ = traffic.ParseServiceSet("ip/" + strconv.Itoa(int(r.ProtocolLow)) + "-" + strconv.Itoa(int(r.ProtocolHigh)))
		}
		if name, ok := c.services[piece.String()]; ok {
			out = append(out, name)
			continue
		}
		name := c.unique(c.naming.Service(r))
		c.created = append(c.created, AddService{Service: firemon.Service{Name: name, Entries: serviceEntries(r)}})
		c.services[piece.String()] = name
		out = append(out, name)
	}
	return slices.Compact(out)
}

func serviceEntries(r traffic.ServiceRange) []firemon.ServiceEntry {
	if r.IsAnyProtocol() {
		return []firemon.ServiceEntry{{AnyProtocol: true}}
	}
	var out []firemon.ServiceEntry
	for p := int(r.ProtocolLow); p <= int(r.ProtocolHigh); p++ {
		out = append(out, firemon.ServiceEntry{Protocol: traffic.Protocol(p), Src: r.Src, Dst: r.Dst})
	}
	return out
}

// wholeOr returns one existing object equal to whole, or the objects for
// part.
func (c *catalog) wholeOr(whole, part traffic.AddressSet) []string {
	if name, ok := c.addresses[whole.String()]; ok {
		return []string{name}
	}
	return c.addressNames(part)
}

// unique returns the sanitized name, or that name with the smallest free
// numeric suffix.
func (c *catalog) unique(name string) string {
	name = c.naming.Sanitize(name)
	candidate := name
	for i := 2; c.taken[candidate]; i++ {
		candidate = name + "_" + strconv.Itoa(i)
	}
	c.taken[candidate] = true
	return candidate
}

// groupAddresses aggregates names into one group when there are at least
// threshold of them; a group already holding exactly set is reused.
func (c *catalog) groupAddresses(names []string, set traffic.AddressSet, group string) []string {
	if len(names) <= 1 || c.threshold < 0 || len(names) < c.threshold {
		return names
	}
	if name, ok := c.addresses[set.String()]; ok && !slices.Contains(names, name) {
		return []string{name}
	}
	name := c.unique(group)
	c.created = append(c.created, AddAddressGroup{Group: firemon.AddressGroup{Name: name, Members: slices.Clone(names)}})
	c.addresses[set.String()] = name
	return []string{name}
}

// groupServices aggregates service names like groupAddresses.
func (c *catalog) groupServices(names []string, set traffic.ServiceSet, group string) []string {
	if len(names) <= 1 || c.threshold < 0 || len(names) < c.threshold {
		return names
	}
	if name, ok := c.services[set.String()]; ok && !slices.Contains(names, name) {
		return []string{name}
	}
	name := c.unique(group)
	c.created = append(c.created, AddServiceGroup{Group: firemon.ServiceGroup{Name: name, Members: slices.Clone(names)}})
	c.services[set.String()] = name
	return []string{name}
}

// mark returns a point rollback can return to.
func (c *catalog) mark() int { return len(c.created) }

// nextRule returns the index of the next rule created for this plan.
// dated returns the next free rule name of the day, KIND-YYYYMMDD-NNN
// (P for permits, B for blocks), numbered after the rules of that day the
// firewall already has.
func (c *catalog) dated(kind string, t time.Time) string {
	prefix := kind + "-" + t.Format("20060102") + "-"
	last := 0
	for name := range c.taken {
		seq, ok := strings.CutPrefix(name, prefix)
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(seq); err == nil && n > last {
			last = n
		}
	}
	return fmt.Sprintf("%s%03d", prefix, last+1)
}

func (c *catalog) nextRule() int {
	c.rules++
	return c.rules - 1
}

// rollback forgets objects created after mark m.
func (c *catalog) rollback(m int) {
	for _, ch := range c.created[m:] {
		switch v := ch.(type) {
		case AddAddressGroup:
			c.forget(v.Group.Name, c.addresses)
		case AddServiceGroup:
			c.forget(v.Group.Name, c.services)
		case AddAddress:
			c.forget(v.Address.Name, c.addresses)
		case AddService:
			c.forget(v.Service.Name, c.services)
		}
	}
	c.created = c.created[:m]
}

func (c *catalog) forget(name string, index map[string]string) {
	delete(c.taken, name)
	for key, n := range index {
		if n == name {
			delete(index, key)
		}
	}
}

// oneAddress returns at most one name for set: NAT rules take a single
// operand, so several objects are always grouped.
func (c *catalog) oneAddress(names []string, set traffic.AddressSet, group string) []string {
	if len(names) <= 1 {
		return names
	}
	if name, ok := c.addresses[set.String()]; ok && !slices.Contains(names, name) {
		return []string{name}
	}
	name := c.unique(group)
	c.created = append(c.created, AddAddressGroup{Group: firemon.AddressGroup{Name: name, Members: slices.Clone(names)}})
	c.addresses[set.String()] = name
	return []string{name}
}

// oneService returns at most one service name for set, like oneAddress.
func (c *catalog) oneService(names []string, set traffic.ServiceSet, group string) []string {
	if len(names) <= 1 {
		return names
	}
	if name, ok := c.services[set.String()]; ok && !slices.Contains(names, name) {
		return []string{name}
	}
	name := c.unique(group)
	c.created = append(c.created, AddServiceGroup{Group: firemon.ServiceGroup{Name: name, Members: slices.Clone(names)}})
	c.services[set.String()] = name
	return []string{name}
}

// anyFor narrows an any side to the address family of the other side when
// the firewall names that family's any with an object (StoneOS Any is
// every IPv4 address): the rule is then written as the device writes it.
// Packets of the other family could not match the other side anyway.
func (c *catalog) anyFor(side, other traffic.AddressSet) traffic.AddressSet {
	if !side.Equal(traffic.AnyAddress()) {
		return side
	}
	for _, family := range []traffic.AddressSet{traffic.AnyIPv4(), traffic.AnyIPv6()} {
		if family.ContainsSet(other) {
			if _, ok := c.addresses[family.String()]; ok {
				return family
			}
		}
	}
	return side
}
