package design

import (
	"net/netip"
	"slices"
	"strconv"

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
}

func newCatalog(fw *firemon.Firewall, naming Naming) *catalog {
	c := &catalog{naming: naming, addresses: map[string]string{}, services: map[string]string{}, taken: map[string]bool{}}
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

// unique returns name, or name with the smallest free numeric suffix.
func (c *catalog) unique(name string) string {
	candidate := name
	for i := 2; c.taken[candidate]; i++ {
		candidate = name + "_" + strconv.Itoa(i)
	}
	c.taken[candidate] = true
	return candidate
}

// mark returns a point rollback can return to.
func (c *catalog) mark() int { return len(c.created) }

// nextRule returns the index of the next rule created for this plan.
func (c *catalog) nextRule() int {
	c.rules++
	return c.rules - 1
}

// rollback forgets objects created after mark m.
func (c *catalog) rollback(m int) {
	for _, ch := range c.created[m:] {
		switch v := ch.(type) {
		case AddAddress:
			delete(c.taken, v.Address.Name)
			for key, name := range c.addresses {
				if name == v.Address.Name {
					delete(c.addresses, key)
				}
			}
		case AddService:
			delete(c.taken, v.Service.Name)
			for key, name := range c.services {
				if name == v.Service.Name {
					delete(c.services, key)
				}
			}
		}
	}
	c.created = c.created[:m]
}
