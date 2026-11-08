package render

import (
	"context"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"net/netip"
	"strconv"
	"strings"
)

func PlainMatch(m fm.Match) bool {
	return m.Schedule == "" && len(m.Applications) == 0 && len(m.Users) == 0 && len(m.Unsupported) == 0 && m.ZoneRelation == fm.AnyZoneRelation
}
func PlainObject(o fm.Object) bool { return !o.Inline && len(o.Unsupported) == 0 && o.ID != "" }
func Number(s string) bool {
	n, err := strconv.ParseUint(s, 10, 32)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}
func Token(s string) (string, error) {
	if s == "" || len(s) > 128 {
		return "", plan.ErrRender
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:/-", r)) {
			return "", plan.ErrRender
		}
	}
	return s, nil
}
func Range(r flow.AddressRange) (string, error) {
	if !r.Valid() || !r.First.Is4() {
		return "", plan.ErrRender
	}
	if r.First == r.Last {
		return r.First.String(), nil
	}
	return r.First.String() + "-" + r.Last.String(), nil
}
func Prefix(r flow.AddressRange) (string, error) {
	if !r.Valid() {
		return "", plan.ErrRender
	}
	for bits := r.First.BitLen(); bits >= 0; bits-- {
		p := netip.PrefixFrom(r.First, bits).Masked()
		v, _ := flow.PrefixRange(p)
		if r == v {
			return p.String(), nil
		}
	}
	return "", plan.ErrRender
}
func Addresses(ctx context.Context, fw *fm.Firewall, refs []fm.AddressRef, any bool) ([]flow.AddressRange, error) {
	if any {
		if len(refs) != 0 {
			return nil, plan.ErrRender
		}
		return nil, nil
	}
	s, k, e := (policy.Engine{}).ResolveAddresses(ctx, fw, refs, false)
	if e != nil {
		return nil, e
	}
	if !k || s.Empty() {
		return nil, plan.ErrRender
	}
	return s.Ranges(), nil
}
func Services(ctx context.Context, fw *fm.Firewall, m fm.Match) ([]fm.ServiceTerm, error) {
	if m.AnyService {
		if len(m.Services) != 0 {
			return nil, plan.ErrRender
		}
		return nil, nil
	}
	s, k, e := (policy.Engine{}).ResolveServices(ctx, fw, m.Services, false)
	if e != nil {
		return nil, e
	}
	if !k || len(s) == 0 {
		return nil, plan.ErrRender
	}
	return s, nil
}

// AppendNAT checks the order emitted by native append-only declaration syntax.
// ASA object NAT has its own derived sort and does not call this helper.
func AppendNAT(before, after *fm.Firewall) error {
	type key struct {
		scope, section string
		stage          int
	}
	added := map[key]bool{}
	for _, e := range after.NATSequence() {
		k := key{e.Scope, e.Order.Section, e.Order.Stage}
		exists := e.Kind == fm.StaticNATObject && before.StaticNAT(e.ID) != nil || e.Kind == fm.DynamicNATObject && before.DynamicNAT(e.ID) != nil
		if exists && added[k] {
			return plan.ErrRender
		}
		if !exists {
			added[k] = true
		}
	}
	return nil
}
