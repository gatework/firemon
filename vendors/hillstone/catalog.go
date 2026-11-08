package hillstone

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

// catalog owns typed native names, including forward references and inline values.
// Accepted object records and their source claims belong to the shared Builder.
type catalog struct {
	doc       *document
	addresses map[fm.ID]fm.Kind
	services  map[fm.ID]fm.Kind
	book      []fm.ServiceRecord
}

func (c *catalog) parse(ctx context.Context, s *config.Builder) error {
	definitions, err := c.doc.definitions(ctx, "address", "service", "servgroup", "schedule")
	if err != nil {
		return err
	}
	if err := c.inventory(ctx, definitions); err != nil {
		return err
	}
	for _, d := range definitions {
		switch d.kind {
		case "address":
			err = c.parseAddress(ctx, s, d)
		case "service":
			err = parseService(ctx, s, d)
		case "servgroup":
			err = c.parseServiceGroup(ctx, s, d)
		case "schedule":
			err = parseSchedule(ctx, s, d)
		}
		if err != nil {
			return err
		}
	}
	book := s.Begin()
	defer book.Rollback()
	for _, service := range c.book {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.HasService(service.ID) || s.HasServiceGroup(service.ID) {
			continue
		}
		book.Emit(fm.Data{Services: []fm.ServiceRecord{service}})
		c.services[service.ID] = fm.ServiceObject
	}
	if err := s.Commit(book); err != nil {
		return err
	}
	return nil
}

func (c *catalog) inventory(ctx context.Context, definitions []definition) error {
	// Inventory every reopening before resolving forward group references.
	for _, d := range definitions {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch d.kind {
		case "address":
			kind := fm.AddressObject
			for _, b := range d.blocks {
				if err := ctx.Err(); err != nil {
					return err
				}
				for _, line := range b.Members {
					if err := ctx.Err(); err != nil {
						return err
					}
					if len(line.Words) == 2 && line.Words[0] == "member" {
						kind = fm.AddressGroupObject
					}
				}
			}
			c.addresses[d.id] = kind
		case "service":
			c.services[d.id] = fm.ServiceObject
		case "servgroup":
			// Native lookup prefers a declared service to a same-name group,
			// independent of which declaration appeared first.
			if c.services[d.id] != fm.ServiceObject {
				c.services[d.id] = fm.ServiceGroupObject
			}
		}
	}
	return ctx.Err()
}

func (c *catalog) parseAddress(ctx context.Context, s *config.Builder, d definition) error {
	r := fm.AddressRecord{Object: d.object()}
	g := fm.AddressGroupRecord{}
	tx := s.Begin()
	defer tx.Rollback()
	if err := d.walk(ctx, tx, &r.Object, func(w []string) bool {
		if len(w) == 2 && w[0] == "ip" {
			if v, err := literal(w[1]); err == nil {
				r.Ranges = append(r.Ranges, v)
				return true
			}
		}
		if len(w) == 3 && w[0] == "range" {
			if v, err := literal(w[1] + "-" + w[2]); err == nil {
				r.Ranges = append(r.Ranges, v)
				return true
			}
		}
		if len(w) == 2 && w[0] == "host" {
			r.FQDN = w[1]
			return true
		}
		if len(w) == 2 && w[0] == "member" {
			g.Members = append(g.Members, c.addressRef(w[1]))
			return true
		}
		return ancillary(w)
	}); err != nil {
		return err
	}
	delta := fm.Data{}
	if len(g.Members) == 0 {
		delta.Addresses = append(delta.Addresses, r)
	} else {
		g.Object = r.Object
		if len(r.Ranges) > 0 || r.FQDN != "" {
			leaf := r
			leaf.ID = fm.ID("$members:" + string(d.id))
			g.Members = append(g.Members, fm.AddressRef{Kind: fm.AddressObject, ID: leaf.ID})
			delta.Addresses = append(delta.Addresses, leaf)
		}
		delta.AddressGroups = append(delta.AddressGroups, g)
	}
	tx.Emit(delta)
	return s.Commit(tx)
}

func parseService(ctx context.Context, s *config.Builder, d definition) error {
	r := fm.ServiceRecord{Object: d.object()}
	tx := s.Begin()
	defer tx.Rollback()
	if err := d.walk(ctx, tx, &r.Object, func(w []string) bool {
		v, ok := term(w)
		if ok {
			r.Terms = append(r.Terms, v)
		}
		return ok || ancillary(w)
	}); err != nil {
		return err
	}
	tx.Emit(fm.Data{Services: []fm.ServiceRecord{r}})
	return s.Commit(tx)
}

func (c *catalog) parseServiceGroup(ctx context.Context, s *config.Builder, d definition) error {
	r := fm.ServiceGroupRecord{Object: d.object()}
	tx := s.Begin()
	defer tx.Rollback()
	if err := d.walk(ctx, tx, &r.Object, func(w []string) bool {
		if len(w) == 2 && w[0] == "service" {
			r.Members = append(r.Members, c.serviceRef(w[1]))
			return true
		}
		return ancillary(w)
	}); err != nil {
		return err
	}
	tx.Emit(fm.Data{ServiceGroups: []fm.ServiceGroupRecord{r}})
	return s.Commit(tx)
}

func (c *catalog) addressRef(name string) fm.AddressRef {
	kind := c.addresses[fm.ID(name)]
	if kind == fm.UnknownObject {
		kind = fm.AddressObject
	}
	return fm.AddressRef{Kind: kind, ID: fm.ID(name)}
}
func (c *catalog) serviceRef(name string) fm.ServiceRef {
	kind := c.services[fm.ID(name)]
	if kind == fm.UnknownObject {
		kind = fm.ServiceObject
	}
	return fm.ServiceRef{Kind: kind, ID: fm.ID(name)}
}
