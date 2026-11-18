package audit

import (
	"github.com/gatework/firemon"
)

// objectFindings reports objects that nothing live references, groups
// first, and objects without any entry or member.
func objectFindings(fw *firemon.Firewall) []Finding {
	var out []Finding
	for _, o := range fw.References().Unused() {
		out = append(out, Finding{Kind: unusedKind(o.Kind), Object: o.Name, ObjectKind: o.Kind})
	}
	cfg := fw.Config()
	empty := func(kind firemon.ObjectKind, name string, predefined bool, n int) {
		if !predefined && n == 0 {
			out = append(out, Finding{Kind: KindEmptyObject, Object: name, ObjectKind: kind})
		}
	}
	for _, a := range cfg.Addresses {
		empty(firemon.ObjectKindAddress, a.Name, a.Predefined, len(a.Entries)+len(a.Invalid))
	}
	for _, g := range cfg.AddressGroups {
		n := len(g.Members) + len(g.Entries) + len(g.Invalid)
		if g.Filter != "" {
			n++
		}
		empty(firemon.ObjectKindAddressGroup, g.Name, g.Predefined, n)
	}
	for _, s := range cfg.Services {
		empty(firemon.ObjectKindService, s.Name, s.Predefined, len(s.Entries)+len(s.Invalid))
	}
	for _, g := range cfg.ServiceGroups {
		empty(firemon.ObjectKindServiceGroup, g.Name, g.Predefined, len(g.Members))
	}
	return out
}

func unusedKind(k firemon.ObjectKind) Kind {
	switch k {
	case firemon.ObjectKindService, firemon.ObjectKindServiceGroup:
		return KindUnusedService
	case firemon.ObjectKindSchedule:
		return KindUnusedSchedule
	case firemon.ObjectKindUnset, firemon.ObjectKindAddress, firemon.ObjectKindAddressGroup:
		return KindUnusedAddress
	default:
		return KindUnusedAddress
	}
}
