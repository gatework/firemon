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
	case ExtendRule:
		i := slices.IndexFunc(cfg.Rules, func(r firemon.SecurityRule) bool { return r.ID == c.RuleID })
		if i < 0 {
			return fmt.Errorf("%w %q", ErrUnknownRule, c.RuleID)
		}
		r := &cfg.Rules[i]
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
