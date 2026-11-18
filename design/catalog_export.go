package design

import (
	"slices"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// Catalog finds existing objects equal to a set and creates the missing
// ones with unique names, for planners outside this package.
type Catalog struct {
	c *catalog
}

// NewCatalog returns a catalog of fw's objects with naming.
func NewCatalog(fw *firemon.Firewall, naming Naming) *Catalog {
	c := newCatalog(fw, naming.withDefaults())
	return &Catalog{c: c}
}

// AddressNames returns object names whose union is exactly s, creating
// objects as needed; nil means any.
func (c *Catalog) AddressNames(s traffic.AddressSet) []string { return c.c.addressNames(s) }

// ServiceNames returns object names whose union is exactly s.
func (c *Catalog) ServiceNames(s traffic.ServiceSet) []string { return c.c.serviceNames(s) }

// Avoid stops reusing an object, for example one the same plan deletes;
// its name stays taken.
func (c *Catalog) Avoid(name string) {
	for _, index := range []map[string]string{c.c.addresses, c.c.services} {
		for key, n := range index {
			if n == name {
				delete(index, key)
			}
		}
	}
}

// Created returns the object creations so far, in dependency order.
func (c *Catalog) Created() []Change { return slices.Clone(c.c.created) }
