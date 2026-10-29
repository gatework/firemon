package policy

import (
	"strconv"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// resolutionCache belongs to one rule-query invocation and one immutable graph.
// It never caches time, zone selection, native VIP reduction or policy outcomes.
// Stored expansion weight is bounded by the same limit as an individual match.
type resolutionCache struct {
	firewall  *fm.Firewall
	remaining int
	addresses map[resolutionKey]addressResolution
	services  map[resolutionKey]serviceResolution
}
type resolutionKey struct {
	count   int
	kind    fm.Kind
	id      fm.ID
	members string
}
type addressResolution struct {
	set   flow.AddressSet
	known bool
	cost  int
}
type serviceResolution struct {
	terms []fm.ServiceTerm
	known bool
	cost  int
}

func addressKey(refs []fm.AddressRef) resolutionKey {
	if len(refs) == 1 {
		return resolutionKey{count: 1, kind: refs[0].Kind, id: refs[0].ID}
	}
	var b strings.Builder
	for _, ref := range refs {
		writeReference(&b, ref.Kind, ref.ID)
	}
	return resolutionKey{count: len(refs), members: b.String()}
}
func serviceKey(refs []fm.ServiceRef) resolutionKey {
	if len(refs) == 1 {
		return resolutionKey{count: 1, kind: refs[0].Kind, id: refs[0].ID}
	}
	var b strings.Builder
	for _, ref := range refs {
		writeReference(&b, ref.Kind, ref.ID)
	}
	return resolutionKey{count: len(refs), members: b.String()}
}
func writeReference(b *strings.Builder, kind fm.Kind, id fm.ID) {
	b.WriteByte(byte(kind))
	b.WriteString(strconv.Itoa(len(id)))
	b.WriteByte(':')
	b.WriteString(string(id))
}
func (c *resolutionCache) retain(cost int) bool {
	weight := max(1, cost)
	if weight > c.remaining {
		return false
	}
	c.remaining -= weight
	return true
}
func (b *resolutionBudget) reuse(cost int) error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	if cost > b.limit-b.spent {
		return ErrBudget
	}
	b.spent += cost
	return nil
}

func resolveAddresses(fw *fm.Firewall, refs []fm.AddressRef, any bool, budget *resolutionBudget) (flow.AddressSet, bool, error) {
	c := budget.cache
	if c == nil || c.firewall != fw || any || len(refs) > budget.limit {
		return expandAddresses(fw, refs, any, budget)
	}
	key := addressKey(refs)
	if cached, ok := c.addresses[key]; ok {
		if err := budget.reuse(cached.cost); err != nil {
			return flow.AddressSet{}, false, err
		}
		return cached.set, cached.known, nil
	}
	spent := budget.spent
	set, known, err := expandAddresses(fw, refs, any, budget)
	cost := budget.spent - spent
	if err == nil && c.retain(cost) {
		if c.addresses == nil {
			c.addresses = make(map[resolutionKey]addressResolution)
		}
		c.addresses[key] = addressResolution{set: set, known: known, cost: cost}
	}
	return set, known, err
}
func resolveServices(fw *fm.Firewall, refs []fm.ServiceRef, any bool, budget *resolutionBudget) ([]fm.ServiceTerm, bool, error) {
	c := budget.cache
	if c == nil || c.firewall != fw || any || len(refs) > budget.limit {
		return expandServices(fw, refs, any, budget)
	}
	key := serviceKey(refs)
	if cached, ok := c.services[key]; ok {
		if err := budget.reuse(cached.cost); err != nil {
			return nil, false, err
		}
		return cached.terms, cached.known, nil
	}
	spent := budget.spent
	terms, known, err := expandServices(fw, refs, any, budget)
	cost := budget.spent - spent
	if err == nil && c.retain(cost) {
		if c.services == nil {
			c.services = make(map[resolutionKey]serviceResolution)
		}
		c.services[key] = serviceResolution{terms: terms, known: known, cost: cost}
	}
	return terms, known, err
}
