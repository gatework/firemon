package query

import (
	"slices"
	"strings"

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
		// An empty object (only unresolved names) touches no address
		// offline; an any object touches every one, shown on request.
		if set.IsEmpty() || (!anyIsMatch && isAny(set)) {
			continue
		}
		if rel := set.Relation(a); rel != traffic.RelationDisjoint {
			u.Objects = append(u.Objects, ObjectUse{Name: name, Relation: rel})
		}
	}
	slices.SortFunc(u.Objects, func(x, y ObjectUse) int { return strings.Compare(x.Name, y.Name) })
	for _, r := range e.rules {
		m := r.Match()
		src, dst := m.Src.Relation(a), m.Dst.Relation(a)
		if !anyIsMatch {
			if isAny(m.Src) {
				src = traffic.RelationDisjoint
			}
			if isAny(m.Dst) {
				dst = traffic.RelationDisjoint
			}
		}
		if src != traffic.RelationDisjoint || dst != traffic.RelationDisjoint {
			u.Rules = append(u.Rules, RuleUse{Rule: r, Source: src, Destination: dst})
		}
	}
	return u
}

// isAny reports every address of a family, or of both: StoneOS Any is
// IPv4 only.
func isAny(s traffic.AddressSet) bool {
	return s.Equal(traffic.AnyAddress()) || s.Equal(traffic.AnyIPv4()) || s.Equal(traffic.AnyIPv6())
}
