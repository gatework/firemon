package hillstone_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/vendors/hillstone"
)

// fidelityBase defines what the rich rules and objects refer to.
const fidelityBase = `zone "inside"
exit
zone "outside"
exit
`

// fidelityItems are rules, objects and schedules with every attribute the
// model keeps.
const fidelityItems = `address "web"
  description "web servers"
  ip 192.0.2.0/24
  range 198.51.100.10 198.51.100.20
  host "www.example.com"
  exclude ip 192.0.2.128/25
exit
address "web-and-more"
  member "web"
  ip 203.0.113.9/32
exit
service "tcp-8080"
  tcp dst-port 8080 8081 src-port 1024 65535
exit
servgroup "web-ports"
  service "tcp-8080"
  service "HTTPS"
exit
schedule "nights"
  absolute start 1/1/2026 00:00:00 end 12/31/2027 23:59:59
exit
schedule "office"
  periodic monday tuesday 08:00:00 to 18:00:00
  periodic daily 22:00:00 to 23:59:59
exit
rule id 7
  action permit
  src-zone "inside"
  dst-zone "outside"
  src-addr "web-and-more"
  src-ip 10.0.0.0/8
  src-range 10.1.1.1 10.1.1.9
  dst-host "api.example.com"
  dst-addr "Any"
  service "web-ports"
  service-rule tcp dst-port 9000
  application "SSH"
  name "rich rule"
  description "ticket 42"
  schedule "office"
  start-time 1/2/2026 08:00:00
  expire-time 12/31/2026 18:00:00
  log session-end
  disable
exit
rule id 8
  action deny
  src-addr "Any"
  dst-addr "Any"
  service "Any"
exit
`

func TestRender_RollbackRestoresEveryAttribute(t *testing.T) {
	t.Parallel()
	orig := mustParse(t, hillstone.Options{}, fidelityBase+fidelityItems)
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
	script, err := hillstone.Renderer{}.Render(&design.Plan{Kind: design.PlanKindCleanup, Changes: changes})
	if err != nil {
		t.Fatal(err)
	}
	restored := mustParse(t, hillstone.Options{}, fidelityBase+strings.Join(script.Rollback, "\n")+"\n")
	byName(orig)
	byName(restored)
	for _, pair := range [][2]any{
		{orig.Rules, restored.Rules}, {orig.Addresses, restored.Addresses}, {orig.AddressGroups, restored.AddressGroups},
		{orig.Services, restored.Services}, {orig.ServiceGroups, restored.ServiceGroups}, {orig.Schedules, restored.Schedules},
	} {
		a, _ := json.Marshal(pair[0])
		b, _ := json.Marshal(pair[1])
		if string(a) != string(b) {
			t.Errorf("rollback differs:\n%s\n%s", a, b)
		}
	}
	if !strings.HasPrefix(script.Commands[0], "no rule id 7") {
		t.Fatalf("commands %v", script.Commands)
	}
}

// byName orders objects by name: their declaration order has no meaning.
func byName(c *firemon.Config) {
	slices.SortFunc(c.Addresses, func(a, b firemon.Address) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(c.AddressGroups, func(a, b firemon.AddressGroup) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(c.Services, func(a, b firemon.Service) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(c.ServiceGroups, func(a, b firemon.ServiceGroup) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(c.Schedules, func(a, b firemon.Schedule) int { return strings.Compare(a.Name, b.Name) })
}
