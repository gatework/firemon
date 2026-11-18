package query

import (
	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

// ObjectUse is an address object or group whose set relates to the
// searched addresses.
type ObjectUse struct {
	Name     string
	Relation traffic.Relation
}

// RuleUse is a security rule whose source or destination relates to the
// searched addresses.
type RuleUse struct {
	Rule *firemon.Rule
	// Source and Destination relate the rule side to the searched set, from
	// the rule's point of view; RelationDisjoint means the side does not
	// touch it.
	Source      traffic.Relation
	Destination traffic.Relation
}

// Usage lists the objects and rules that touch an address set.
type Usage struct {
	Objects []ObjectUse
	Rules   []RuleUse
}

// Usage finds the address objects and security rules whose addresses
// overlap a, in name and rule order. Rules matching any address on a side
// are reported only when anyIsMatch is true.
func (e *Engine) Usage(a traffic.AddressSet, anyIsMatch bool) Usage {
	var u Usage
	for name, set := range e.fw.Addresses() {
		if rel := set.Relation(a); rel != traffic.RelationDisjoint {
			u.Objects = append(u.Objects, ObjectUse{Name: name, Relation: rel})
		}
	}
	all := traffic.AnyAddress()
	for _, r := range e.rules {
		m := r.Match()
		src, dst := m.Src.Relation(a), m.Dst.Relation(a)
		if !anyIsMatch {
			if m.Src.Equal(all) {
				src = traffic.RelationDisjoint
			}
			if m.Dst.Equal(all) {
				dst = traffic.RelationDisjoint
			}
		}
		if src != traffic.RelationDisjoint || dst != traffic.RelationDisjoint {
			u.Rules = append(u.Rules, RuleUse{Rule: r, Source: src, Destination: dst})
		}
	}
	return u
}
