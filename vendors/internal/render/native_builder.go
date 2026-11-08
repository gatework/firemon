package render

import (
	"context"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
)

// Owner identifies a new native NAT declaration or policy. Its two alternatives
// stay separate from the persisted firewall object kinds.
type Owner struct {
	nat  fm.NATRef
	rule fm.ID
}

func NATOwner(ref fm.NATRef) Owner { return Owner{nat: ref} }
func PolicyOwner(id fm.ID) Owner   { return Owner{rule: id} }

type declaration struct {
	kind fm.Kind
	id   fm.ID
}

// NativeBuilder owns generated declarations and policy attachments for one
// validated native delta. Adapters retain syntax and emission order; the builder
// checks that every suppressed declaration belongs to an actual new owner.
type NativeBuilder struct {
	before, after *fm.Firewall
	vendor        string
	changes       []plan.Change
	clock         *fm.ScheduleClock
	addresses     []fm.ID
	services      []fm.ID
	references    map[declaration]map[Owner]bool
	claims        map[declaration]bool
	owners        map[Owner]bool
	commands      []string
	policy        map[fm.ID][]string
}

func NewNativeBuilder(ctx context.Context, vendor string, before, after *fm.Firewall, c plan.NativeChanges) (*NativeBuilder, error) {
	if err := plan.ValidateNativeChanges(ctx, before, after, c); err != nil {
		return nil, err
	}
	if before.Metadata().Vendor != vendor || vendor == "fortinet" && before.Metadata().Context == "" {
		return nil, plan.ErrInvalid
	}
	b := &NativeBuilder{before: before, after: after, vendor: vendor, changes: cloneChanges(c.Rules),
		references: make(map[declaration]map[Owner]bool), claims: make(map[declaration]bool), owners: make(map[Owner]bool), policy: make(map[fm.ID][]string)}
	if c.Clock != nil {
		clock := *c.Clock
		b.clock = &clock
	}
	for _, r := range c.Additions.Rules {
		b.addOwner(PolicyOwner(r.ID), after.Rule(r.ID).Record().Match)
	}
	for _, r := range c.Additions.StaticNATs {
		b.addOwner(NATOwner(fm.NATRef{Kind: fm.StaticNATObject, ID: r.ID}), after.StaticNAT(r.ID).Record().Match)
	}
	for _, r := range c.Additions.DynamicNATs {
		b.addOwner(NATOwner(fm.NATRef{Kind: fm.DynamicNATObject, ID: r.ID}), after.DynamicNAT(r.ID).Record().Match)
	}
	for _, a := range c.Additions.Addresses {
		b.addresses = append(b.addresses, a.ID)
		if ref := after.Address(a.ID).Record().VIP; ref != (fm.NATRef{}) {
			b.reference(declaration{fm.AddressObject, a.ID}, NATOwner(ref))
		}
	}
	for _, s := range c.Additions.Services {
		b.services = append(b.services, s.ID)
	}
	return b, ctx.Err()
}

func (b *NativeBuilder) addOwner(owner Owner, m fm.Match) {
	b.owners[owner] = true
	for _, refs := range [][]fm.AddressRef{m.Sources, m.Destinations} {
		for _, ref := range refs {
			b.reference(declaration{ref.Kind, ref.ID}, owner)
		}
	}
	for _, ref := range m.Services {
		b.reference(declaration{ref.Kind, ref.ID}, owner)
	}
}

func (b *NativeBuilder) reference(d declaration, owner Owner) {
	if b.references[d] == nil {
		b.references[d] = make(map[Owner]bool)
	}
	b.references[d][owner] = true
}

func (b *NativeBuilder) claim(owner Owner, d declaration) error {
	if b == nil || !b.owners[owner] || !b.references[d][owner] {
		return plan.ErrRender
	}
	b.claims[d] = true
	return nil
}

// ClaimAddress permits shared literal values when each claiming owner actually
// references them. VIP ownership uses the typed association, never ID equality.
func (b *NativeBuilder) ClaimAddress(owner Owner, ref fm.AddressRef) error {
	if b == nil || ref.Kind != fm.AddressObject || b.after.Address(ref.ID) == nil {
		return plan.ErrRender
	}
	return b.claim(owner, declaration{ref.Kind, ref.ID})
}

func (b *NativeBuilder) ClaimService(owner Owner, ref fm.ServiceRef) error {
	if b == nil || ref.Kind != fm.ServiceObject || b.after.Service(ref.ID) == nil {
		return plan.ErrRender
	}
	return b.claim(owner, declaration{ref.Kind, ref.ID})
}

func (b *NativeBuilder) AttachPolicy(ref fm.NATRef, rule fm.ID, commands []string) error {
	if b == nil || ref.Kind != fm.DynamicNATObject || !b.owners[NATOwner(ref)] || !b.owners[PolicyOwner(rule)] || b.policy[rule] != nil || len(commands) == 0 {
		return plan.ErrRender
	}
	if b.after.DynamicNAT(ref.ID).Record().Rule != rule {
		return plan.ErrRender
	}
	b.policy[rule] = slices.Clone(commands)
	return nil
}

func (b *NativeBuilder) AppendCommands(commands ...string) {
	b.commands = append(b.commands, commands...)
}

func (b *NativeBuilder) Prepare(ctx context.Context) (Batch, error) {
	if b == nil {
		return Batch{}, plan.ErrInvalid
	}
	prepared, err := prepare(ctx, b.vendor, b.before, b.after, b.changes)
	if err != nil {
		return Batch{}, err
	}
	for _, id := range b.addresses {
		if b.claims[declaration{fm.AddressObject, id}] {
			continue
		}
		if b.after.Address(id).Record().Inline {
			return Batch{}, plan.ErrRender
		}
		prepared.addresses[id] = true
	}
	for _, id := range b.services {
		if b.claims[declaration{fm.ServiceObject, id}] {
			continue
		}
		if b.after.Service(id).Record().Inline {
			return Batch{}, plan.ErrRender
		}
		prepared.services[id] = true
	}
	prepared.generatedAddresses = make(map[fm.ID]bool)
	for d := range b.claims {
		switch d.kind {
		case fm.AddressObject:
			delete(prepared.addresses, d.id)
			prepared.generatedAddresses[d.id] = true
		case fm.ServiceObject:
			delete(prepared.services, d.id)
		}
	}
	if err := prepared.validateNames(ctx, b.before, b.after); err != nil {
		return Batch{}, err
	}
	prepared.native = true
	prepared.commands = slices.Clone(b.commands)
	prepared.policy = make(map[fm.ID][]string, len(b.policy))
	for id, commands := range b.policy {
		prepared.policy[id] = slices.Clone(commands)
	}
	if b.clock != nil {
		clock := *b.clock
		prepared.clock = &clock
	}
	return prepared, ctx.Err()
}

func cloneChanges(changes []plan.Change) []plan.Change {
	out := slices.Clone(changes)
	for i := range out {
		out[i].Sources = slices.Clone(out[i].Sources)
		out[i].Destinations = slices.Clone(out[i].Destinations)
		out[i].Services = slices.Clone(out[i].Services)
	}
	return out
}
