package design

import (
	"errors"
	"fmt"
	"slices"

	"github.com/gatework/firemon"
)

// ErrUnknownRule reports a change that refers to a rule the configuration
// does not have.
var ErrUnknownRule = errors.New("design: unknown rule")

// Apply performs changes on cfg in order.
func Apply(cfg *firemon.Config, changes []Change) error {
	for _, ch := range changes {
		if err := apply(cfg, ch); err != nil {
			return err
		}
	}
	return nil
}

func apply(cfg *firemon.Config, ch Change) error {
	switch c := ch.(type) {
	case AddAddress:
		cfg.Addresses = append(cfg.Addresses, c.Address)
	case AddService:
		cfg.Services = append(cfg.Services, c.Service)
	case AddAddressGroup:
		cfg.AddressGroups = append(cfg.AddressGroups, c.Group)
	case AddServiceGroup:
		cfg.ServiceGroups = append(cfg.ServiceGroups, c.Group)
	case ExtendRule:
		i := slices.IndexFunc(cfg.Rules, func(r firemon.SecurityRule) bool { return r.ID == c.RuleID })
		if i < 0 {
			return fmt.Errorf("%w %q", ErrUnknownRule, c.RuleID)
		}
		r := &cfg.Rules[i]
		if extendsAny(r, c.Field) {
			// An empty list means any: appending names would narrow it.
			return fmt.Errorf("design: extend rule %q: %s already matches any", c.RuleID, c.Field)
		}
		switch c.Field {
		case FieldSource:
			for _, n := range c.Names {
				r.Source = append(r.Source, firemon.NamedAddress(n))
			}
		case FieldDestination:
			for _, n := range c.Names {
				r.Destination = append(r.Destination, firemon.NamedAddress(n))
			}
		case FieldService:
			r.Services = append(r.Services, c.Names...)
		case FieldUnset:
			return fmt.Errorf("design: extend rule %q: field unset", c.RuleID)
		}
	case AddNAT:
		return applyNAT(cfg, c)
	case AddStaticNAT:
		cfg.StaticNATs = append(cfg.StaticNATs, c.Mapping)
	case AddRule:
		at := len(cfg.Rules)
		if c.Before != "" {
			at = slices.IndexFunc(cfg.Rules, func(r firemon.SecurityRule) bool { return r.ID == c.Before })
			if at < 0 {
				return fmt.Errorf("%w %q", ErrUnknownRule, c.Before)
			}
		}
		cfg.Rules = slices.Insert(cfg.Rules, at, c.Rule)
	default:
		return fmt.Errorf("design: unsupported change %T", ch)
	}
	return nil
}

// extendsAny reports whether field of r is empty, which means any.
func extendsAny(r *firemon.SecurityRule, f Field) bool {
	switch f {
	case FieldSource:
		return len(r.Source) == 0
	case FieldDestination:
		return len(r.Destination) == 0
	case FieldService:
		return len(r.Services) == 0 && len(r.ServiceEntries) == 0
	case FieldUnset:
		return false
	default:
		return false
	}
}

// ErrUnknownNAT reports a NAT change placed before a rule the
// configuration does not have.
var ErrUnknownNAT = errors.New("design: unknown NAT rule")

// applyNAT inserts c.Rule into its NAT list and, on single-order vendors,
// renumbers the precedences to the new order.
func applyNAT(cfg *firemon.Config, c AddNAT) error {
	single := cfg.Semantics.NATOrder == firemon.NATOrderSingle
	at := len(cfg.DynamicNATs)
	if c.Before != "" {
		at = slices.IndexFunc(cfg.DynamicNATs, func(n firemon.DynamicNAT) bool {
			return n.ID == c.Before && (single || NATSide(n) == NATSide(c.Rule))
		})
		if at < 0 {
			return fmt.Errorf("%w %q", ErrUnknownNAT, c.Before)
		}
	}
	cfg.DynamicNATs = slices.Insert(cfg.DynamicNATs, at, c.Rule)
	if c.Bidirectional && len(c.Rule.Source) == 1 && len(c.Rule.TranslatedSource.Addresses) == 1 {
		r := c.Rule
		cfg.StaticNATs = append(cfg.StaticNATs, firemon.StaticNAT{
			ID: r.ID, Name: r.Name, Real: r.Source[0], Mapped: r.TranslatedSource.Addresses[0], Zones: slices.Clone(r.To),
			Disabled: r.Disabled, InboundOnly: true,
		})
	}
	if single {
		renumber(cfg)
	}
	return nil
}

// renumber gives single-list NAT rules precedences in list order; the
// reverse halves of bi-directional rules follow their rule.
func renumber(cfg *firemon.Config) {
	byID := make(map[string]int, len(cfg.DynamicNATs))
	for i := range cfg.DynamicNATs {
		cfg.DynamicNATs[i].Precedence = i + 1
		byID[cfg.DynamicNATs[i].ID] = i + 1
	}
	for i := range cfg.StaticNATs {
		if p, ok := byID[cfg.StaticNATs[i].ID]; ok && cfg.StaticNATs[i].InboundOnly {
			cfg.StaticNATs[i].Precedence = p
		}
	}
}

// NATSide returns the list a dynamic NAT rule belongs to on
// separate-order vendors: destination when it translates destinations,
// source otherwise.
func NATSide(n firemon.DynamicNAT) firemon.NATKind {
	if m := n.TranslatedDestination.Mode; m != firemon.TranslationModeUnset && m != firemon.TranslationModeNone {
		return firemon.NATKindDestination
	}
	return firemon.NATKindSource
}
