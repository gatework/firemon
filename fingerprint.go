package firemon

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
)

// Fingerprint returns a digest of the policy-relevant configuration: every
// field of Config except diagnostics, with declaration order ignored where
// it carries no meaning (objects, zones, interfaces, routes) and kept where
// it does (rules, NAT). Two configurations with the same
// fingerprint compile to the same firewall. Design plans record it as their
// baseline so deployment can detect configuration drift.
func (fw *Firewall) Fingerprint() string { return fw.fingerprint }

func fingerprint(cfg *Config) string {
	c := *cfg.Clone()
	c.Diagnostics = nil
	c.Source = nil // how the text is written does not change the firewall
	byName := func(a, b string) int { return strings.Compare(a, b) }
	slices.SortFunc(c.VirtualRouters, func(a, b VirtualRouter) int { return byName(a.Name, b.Name) })
	slices.SortFunc(c.Zones, func(a, b Zone) int { return byName(a.Name, b.Name) })
	slices.SortFunc(c.Interfaces, func(a, b Interface) int { return byName(a.Name, b.Name) })
	slices.SortFunc(c.Addresses, func(a, b Address) int { return byName(a.Name, b.Name) })
	slices.SortFunc(c.AddressGroups, func(a, b AddressGroup) int { return byName(a.Name, b.Name) })
	slices.SortFunc(c.Services, func(a, b Service) int { return byName(a.Name, b.Name) })
	slices.SortFunc(c.ServiceGroups, func(a, b ServiceGroup) int { return byName(a.Name, b.Name) })
	slices.SortFunc(c.Schedules, func(a, b Schedule) int { return byName(a.Name, b.Name) })
	slices.SortFunc(c.RuleGroups, func(a, b RuleGroup) int { return byName(a.ID, b.ID) })
	slices.SortFunc(c.Routes, func(a, b Route) int {
		return cmp.Or(byName(a.VirtualRouter, b.VirtualRouter), byName(a.Destination.String(), b.Destination.String()),
			byName(a.NextHop.String(), b.NextHop.String()), byName(a.Interface, b.Interface),
			byName(a.NextVirtualRouter, b.NextVirtualRouter), cmp.Compare(a.Distance, b.Distance),
			cmp.Compare(a.Metric, b.Metric), compareBool(a.Discard, b.Discard), slices.Compare(a.Objects, b.Objects))
	})
	slices.SortFunc(c.PolicyBindings, func(a, b PolicyBinding) int {
		return cmp.Or(byName(a.Policy, b.Policy), byName(a.Zone, b.Zone), byName(a.Interface, b.Interface))
	})
	raw, err := json.Marshal(&c)
	if err != nil {
		// Config holds only marshalable values; failure is a programming defect.
		panic("firemon: fingerprint: " + err.Error())
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	default:
		return -1
	}
}
