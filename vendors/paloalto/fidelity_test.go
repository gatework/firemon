package paloalto_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/vendors/paloalto"
)

const fidelityBase = `set zone trust network layer3 ethernet1/2
set zone untrust network layer3 ethernet1/1
`

const fidelityItems = `set address web ip-netmask 192.0.2.0/24
set address web-range ip-range 198.51.100.10-198.51.100.20
set address api fqdn api.example.com
set address-group web-farm static [ web web-range ]
set address-group tagged dynamic filter 'prod'
set service tcp-8080 protocol tcp port 8080-8081 source-port 1024-65535
set service-group web-ports members [ tcp-8080 service-https ]
set schedule window schedule-type non-recurring [ 2026/01/01@00:00-2027/12/31@23:59 ]
set schedule office schedule-type recurring weekly monday [ 08:00-17:59 ]
set schedule office schedule-type recurring weekly tuesday [ 08:00-17:59 ]
set rulebase security rules rich from trust
set rulebase security rules rich to untrust
set rulebase security rules rich source [ web-farm 10.0.0.0/8 10.1.1.1-10.1.1.9 ]
set rulebase security rules rich destination api
set rulebase security rules rich application [ ssl web-browsing ]
set rulebase security rules rich service [ web-ports application-default ]
set rulebase security rules rich action allow
set rulebase security rules rich negate-destination yes
set rulebase security rules rich rule-type interzone
set rulebase security rules rich description "ticket 42"
set rulebase security rules rich schedule office
set rulebase security rules rich group-tag web
set rulebase security rules rich log-end yes
set rulebase security rules rich disabled yes
set rulebase security rules last from any
set rulebase security rules last to any
set rulebase security rules last source any
set rulebase security rules last destination any
set rulebase security rules last application any
set rulebase security rules last service any
set rulebase security rules last action deny
`

func TestRender_RollbackRestoresEveryAttribute(t *testing.T) {
	t.Parallel()
	orig, _ := compileSet(t, fidelityBase+fidelityItems)
	var changes []design.Change
	for i, r := range orig.Rules {
		next := ""
		if i+1 < len(orig.Rules) {
			next = orig.Rules[i+1].ID
		}
		changes = append(changes, design.DeleteRule{Rule: r, Next: next})
	}
	for _, g := range orig.AddressGroups {
		changes = append(changes, design.DeleteAddressGroup{Group: g})
	}
	for _, a := range orig.Addresses {
		if !a.Predefined {
			changes = append(changes, design.DeleteAddress{Address: a})
		}
	}
	for _, g := range orig.ServiceGroups {
		changes = append(changes, design.DeleteServiceGroup{Group: g})
	}
	for _, s := range orig.Services {
		if !s.Predefined {
			changes = append(changes, design.DeleteService{Service: s})
		}
	}
	for _, s := range orig.Schedules {
		changes = append(changes, design.DeleteSchedule{Schedule: s})
	}
	script, err := paloalto.Renderer{}.Render(&design.Plan{Kind: design.PlanKindCleanup, Changes: changes})
	if err != nil {
		t.Fatal(err)
	}
	// A readback lists rules in order: apply the moves the rollback asks for.
	restored, _ := compileSet(t, fidelityBase+strings.Join(setLines(script.Rollback), "\n")+"\n")
	applyMoves(restored, script.Rollback)
	sortByName(orig)
	sortByName(restored)
	for _, pair := range [][2]any{
		{orig.Rules, restored.Rules}, {orig.Addresses, restored.Addresses}, {orig.AddressGroups, restored.AddressGroups},
		{orig.Services, restored.Services}, {orig.ServiceGroups, restored.ServiceGroups}, {orig.Schedules, restored.Schedules},
	} {
		if !equalJSON(t, pair[0], pair[1]) {
			a, _ := json.Marshal(pair[0])
			b, _ := json.Marshal(pair[1])
			t.Errorf("rollback differs:\n%s\n%s", a, b)
		}
	}
}

func setLines(cmds []string) []string {
	return slices.DeleteFunc(slices.Clone(cmds), func(c string) bool { return !strings.HasPrefix(c, "set ") })
}

// applyMoves performs "move rulebase security rules X before Y".
func applyMoves(cfg *firemon.Config, cmds []string) {
	for _, c := range cmds {
		f := strings.Fields(c)
		if len(f) != 7 || f[0] != "move" || f[2] != "security" || f[5] != "before" {
			continue
		}
		i := slices.IndexFunc(cfg.Rules, func(r firemon.SecurityRule) bool { return r.ID == f[4] })
		r := cfg.Rules[i]
		cfg.Rules = slices.Delete(cfg.Rules, i, i+1)
		j := slices.IndexFunc(cfg.Rules, func(r firemon.SecurityRule) bool { return r.ID == f[6] })
		cfg.Rules = slices.Insert(cfg.Rules, j, r)
	}
}

func sortByName(c *firemon.Config) {
	slices.SortFunc(c.Addresses, func(a, b firemon.Address) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(c.AddressGroups, func(a, b firemon.AddressGroup) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(c.Services, func(a, b firemon.Service) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(c.ServiceGroups, func(a, b firemon.ServiceGroup) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(c.Schedules, func(a, b firemon.Schedule) int { return strings.Compare(a.Name, b.Name) })
}
