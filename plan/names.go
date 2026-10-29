package plan

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/internal/nativename"
)

// nameAllocator belongs to one candidate draft. Reservations include pending
// declarations, so allocation never depends on when they enter the draft tables.
type nameAllocator struct {
	visits    *visitBudget
	vendor    string
	addresses map[string]bool
	services  map[string]bool
	ruleIDs   map[fm.ID]bool
	ruleNames map[nativename.RuleKey]bool
}

func newNameAllocator(ctx context.Context, data *fm.Data, visits *visitBudget) (*nameAllocator, error) {
	count := len(data.Addresses) + len(data.AddressGroups) + len(data.Services) + len(data.ServiceGroups) + len(data.Rules)
	if err := visits.take(ctx, count); err != nil {
		return nil, err
	}
	n := &nameAllocator{
		visits: visits, vendor: data.Metadata.Vendor,
		addresses: make(map[string]bool), services: make(map[string]bool),
		ruleIDs: make(map[fm.ID]bool), ruleNames: make(map[nativename.RuleKey]bool),
	}
	// Generated global objects must also avoid local names that could shadow
	// them in a zone's address book. Reserve both IDs and names across scopes.
	reserve := func(names map[string]bool, object fm.Object) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		names[string(object.ID)], names[nativename.Name(object)] = true, true
		return nil
	}
	for _, address := range data.Addresses {
		if err := reserve(n.addresses, address.Object); err != nil {
			return nil, err
		}
	}
	for _, group := range data.AddressGroups {
		if err := reserve(n.addresses, group.Object); err != nil {
			return nil, err
		}
	}
	for _, service := range data.Services {
		if err := reserve(n.services, service.Object); err != nil {
			return nil, err
		}
	}
	for _, group := range data.ServiceGroups {
		if err := reserve(n.services, group.Object); err != nil {
			return nil, err
		}
	}
	for _, rule := range data.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n.ruleIDs[rule.ID] = true
		if nativename.NamedRules(n.vendor) {
			n.ruleNames[nativename.Rule(n.vendor, rule)] = true
		}
	}
	return n, nil
}

func (n *nameAllocator) object(ctx context.Context, id fm.ID, names map[string]bool) (fm.ID, error) {
	for {
		if err := n.visits.take(ctx, 1); err != nil {
			return "", err
		}
		if !names[string(id)] {
			if err := n.visits.take(ctx, 1); err != nil {
				return "", err
			}
			names[string(id)] = true
			return id, nil
		}
		id += "-new"
	}
}

func (n *nameAllocator) rule(ctx context.Context, id fm.ID, rule fm.RuleRecord) (fm.ID, error) {
	for {
		if err := n.visits.take(ctx, 1); err != nil {
			return "", err
		}
		rule.ID, rule.Name = id, string(id)
		key := nativename.Rule(n.vendor, rule)
		if !n.ruleIDs[id] && (!nativename.NamedRules(n.vendor) || !n.ruleNames[key]) {
			if err := n.visits.take(ctx, 1); err != nil {
				return "", err
			}
			n.ruleIDs[id] = true
			if nativename.NamedRules(n.vendor) {
				n.ruleNames[key] = true
			}
			return id, nil
		}
		id += "-new"
	}
}
