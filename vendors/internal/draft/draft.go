// Package draft maintains parser-local accepted records without exporting a session graph.
package draft

import fm "github.com/gatework/firemon"

// Append copies the newly accepted records; earlier records remain parser-owned.
func Append(dst *fm.Data, accepted fm.Data) {
	d := accepted.Clone()
	dst.Diagnostics = append(dst.Diagnostics, d.Diagnostics...)
	dst.Zones = append(dst.Zones, d.Zones...)
	dst.Interfaces = append(dst.Interfaces, d.Interfaces...)
	dst.Routes = append(dst.Routes, d.Routes...)
	dst.Addresses = append(dst.Addresses, d.Addresses...)
	dst.AddressGroups = append(dst.AddressGroups, d.AddressGroups...)
	dst.Services = append(dst.Services, d.Services...)
	dst.ServiceGroups = append(dst.ServiceGroups, d.ServiceGroups...)
	dst.Schedules = append(dst.Schedules, d.Schedules...)
	dst.Rules = append(dst.Rules, d.Rules...)
	dst.RuleBindings = append(dst.RuleBindings, d.RuleBindings...)
	dst.StaticNATs = append(dst.StaticNATs, d.StaticNATs...)
	dst.DynamicNATs = append(dst.DynamicNATs, d.DynamicNATs...)
	dst.NATPools = append(dst.NATPools, d.NATPools...)
}
