package vendors_test

import (
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/analysis"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
)

type migrationFixture struct{ vendor, version, topology, declaration, from, to, scope, chain string }

// Native declarations below are authored from the intended HTTPS behavior,
// independently of renderer commands. Only newly allocated names are substituted.
func migrationFixtures(t *testing.T) []migrationFixture {
	fixtures := []migrationFixture{
		{vendor: "hillstone", version: "5.5R8", topology: nativeCaseNamed(t, "hillstone-bnat").before, from: "inside", to: "outside", declaration: `address CLIENT
 ip 192.0.2.10/32
exit
address SERVER
 ip 198.51.100.20/32
exit
service WEB
 tcp dst-port 443 443
exit
policy-global
 rule id 20
 src-zone inside
 dst-zone outside
 src-addr CLIENT
 dst-addr SERVER
 service WEB
 action permit
 exit
exit
`},
		{vendor: "srx", version: "21.4R3", topology: nativeCaseNamed(t, "srx-static").before, from: "inside", to: "outside", declaration: `set security address-book global address CLIENT 192.0.2.10/32
set security address-book global address SERVER 198.51.100.20/32
set applications application WEB protocol tcp
set applications application WEB source-port 0-65535
set applications application WEB destination-port 443
set security policies from-zone inside to-zone outside policy RULE match source-address CLIENT
set security policies from-zone inside to-zone outside policy RULE match destination-address SERVER
set security policies from-zone inside to-zone outside policy RULE match application WEB
set security policies from-zone inside to-zone outside policy RULE then permit
`},
		{vendor: "asa", version: "9.16(4)", topology: nativeCaseNamed(t, "asa-object-static").before, from: "inside", to: "outside", chain: "IN", declaration: `object network CLIENT
 host 192.0.2.10
!
object network SERVER
 host 198.51.100.20
!
object service WEB
 service tcp destination eq 443
!
access-list IN extended permit object WEB object CLIENT object SERVER
access-group IN in interface inside
`},
		{vendor: "netscreen", version: "6.3.0", topology: nativeCaseNamed(t, "netscreen-mip").before, from: "Trust", to: "Untrust", declaration: `set address Global CLIENT 192.0.2.10/32
set address Global SERVER 198.51.100.20/32
set service WEB protocol tcp src-port 0-65535 dst-port 443-443
set policy id 20 name RULE from Trust to Untrust CLIENT SERVER WEB permit
exit
`},
		{vendor: "fortinet", version: "7.2.8", topology: nativeCaseNamed(t, "fortinet-vip").before, from: "lan1", to: "wan1", scope: "root", declaration: `config firewall address
edit CLIENT
set subnet 192.0.2.10 255.255.255.255
next
edit SERVER
set subnet 198.51.100.20 255.255.255.255
next
end
config firewall service custom
edit WEB
set tcp-portrange 443:0-65535
next
end
config firewall policy
edit 20
set name RULE
set srcintf lan1
set dstintf wan1
set srcaddr CLIENT
set dstaddr SERVER
set service WEB
set schedule always
set action accept
set logtraffic disable
next
end
`},
		{vendor: "huawei", version: "V500R005", topology: nativeCaseNamed(t, "huawei-server-map").before, from: "trust", to: "untrust", declaration: `ip address-set CLIENT type object
 address 0 192.0.2.10 mask 32
#
ip address-set SERVER type object
 address 0 198.51.100.20 mask 32
#
ip service-set WEB type object
 service 0 protocol tcp source-port 0 to 65535 destination-port 443
#
security-policy
 rule name RULE
  source-zone trust
  destination-zone untrust
  source-address address-set CLIENT
  destination-address address-set SERVER
  service WEB
  action permit
#
`},
		{vendor: "paloalto", version: "10.2.0", from: "inside", to: "outside", topology: `set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24
set network interface ethernet ethernet1/2 layer3 ip 198.51.100.1/24
set zone inside network layer3 ethernet1/1
set zone outside network layer3 ethernet1/2
`, declaration: `set address CLIENT ip-netmask 192.0.2.10/32
set address SERVER ip-netmask 198.51.100.20/32
set service WEB protocol tcp source-port 0-65535
set service WEB protocol tcp port 443
set rulebase security rules RULE from inside
set rulebase security rules RULE to outside
set rulebase security rules RULE source CLIENT
set rulebase security rules RULE destination SERVER
set rulebase security rules RULE application any
set rulebase security rules RULE service WEB
set rulebase security rules RULE action allow
set rulebase security rules RULE log-start no
set rulebase security rules RULE log-end no
`},
	}
	for i := range fixtures {
		if fixtures[i].chain == "" {
			fixtures[i].chain = "security"
		}
	}
	return fixtures
}
func (f migrationFixture) native(client, server, web, rule string) string {
	return strings.NewReplacer("CLIENT", client, "SERVER", server, "WEB", web, "RULE", rule).Replace(f.declaration)
}

func (f migrationFixture) scheduled(schedule, client, server, web, rule string) string {
	text := f.declaration
	switch f.vendor {
	case "hillstone":
		text = strings.Replace(text, " service WEB\n", " service WEB\n schedule "+schedule+"\n", 1)
	case "srx":
		text += "set security policies from-zone inside to-zone outside policy RULE scheduler-name " + schedule + "\n"
	case "asa":
		text = strings.Replace(text, "object SERVER\naccess-group", "object SERVER time-range "+schedule+"\naccess-group", 1)
	case "netscreen":
		text = strings.Replace(text, "WEB permit", "WEB permit schedule "+schedule, 1)
	case "fortinet":
		text = strings.Replace(text, "set schedule always", "set schedule "+schedule, 1)
	case "huawei":
		text = strings.Replace(text, "  action permit", "  time-range "+schedule+"\n  action permit", 1)
	case "paloalto":
		text += "set rulebase security rules RULE schedule " + schedule + "\n"
	}
	return strings.NewReplacer("CLIENT", client, "SERVER", server, "WEB", web, "RULE", rule).Replace(text)
}

func TestMigrationRecurringScheduleToSevenNativeTargets(t *testing.T) {
	fixtures := migrationFixtures(t)
	src := fixtures[1] // Junos weekday scheduler, independently captured with policy.
	var sourceWeekly string
	for _, tc := range weeklyCases() {
		if tc.vendor == src.vendor {
			sourceWeekly = tc.raw
		}
	}
	source, _ := scheduleCapture(t, src.vendor, src.version, src.topology+sourceWeekly+src.scheduled("office", "client", "server", "https", "allow"), true)
	if !source.Complete() {
		t.Fatal(source.Diagnostics())
	}
	at := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	for _, dst := range fixtures {
		t.Run(dst.vendor, func(t *testing.T) {
			baseline := dst.topology
			if dst.vendor == "asa" {
				baseline += "access-list IN extended deny ip any4 any4\naccess-group IN in interface inside\n"
			}
			target, clock := scheduleCapture(t, dst.vendor, dst.version, baseline, true)
			targetChain := fm.PolicyChain{Scope: dst.scope, RuleSet: dst.chain}
			if dst.vendor == "paloalto" {
				for r := range target.OrderedRules() {
					targetChain = r.Chain()
					break
				}
			}
			var sourceChain fm.PolicyChain
			for r := range source.DeclaredRules() {
				if !r.Builtin() {
					sourceChain = r.Chain()
					break
				}
			}
			request := analysis.MigrationRequest{At: at, Clock: &clock, Zones: map[fm.ID]fm.ID{fm.ID(src.from): fm.ID(dst.from), fm.ID(src.to): fm.ID(dst.to)}, Chains: map[fm.PolicyChain]fm.PolicyChain{sourceChain: targetChain}, Pairs: []analysis.ZonePair{{From: fm.ID(src.from), To: fm.ID(src.to)}}}
			if dst.vendor == "asa" {
				request.Zones[fm.ID(src.to)] = ""
			}
			renderer, _ := vendors.Renderer(dst.vendor)
			result, err := (analysis.Migrator{Planner: plan.Planner{Renderer: renderer}}).Plan(t.Context(), source, target, request)
			if err != nil {
				t.Fatal(err)
			}
			if result.Plan == nil {
				t.Fatalf("schedule migration rejected: %+v", result.Issues)
			}
			p := result.Plan
			r := p.After().Rule(p.Changes()[0].Rule).Record()
			if r.Match.Schedule == "" {
				t.Fatal("schedule dropped")
			}
			client, server, web := p.After().Address(r.Match.Sources[0].ID).Name(), p.After().Address(r.Match.Destinations[0].ID).Name(), p.After().Service(r.Match.Services[0].ID).Name()
			var weekly string
			for _, tc := range weeklyCases() {
				if tc.vendor == dst.vendor {
					weekly = strings.ReplaceAll(tc.raw, "office", string(r.Match.Schedule))
				}
			}
			raw := dst.topology + weekly + dst.scheduled(string(r.Match.Schedule), client, server, web, r.Name)
			if dst.vendor == "asa" {
				raw += "access-list IN extended deny ip any4 any4\n"
			}
			observed, _ := scheduleCapture(t, dst.vendor, dst.version, raw, true)
			if !observed.Complete() {
				t.Fatal(observed.Diagnostics())
			}
			if _, err := p.Verify(t.Context(), observed); err != nil {
				t.Fatalf("independent scheduled capture: %v", err)
			}
			q := policy.Request{Scope: targetChain.Scope, RuleSet: targetChain.RuleSet, FromZone: fm.ID(dst.from), ToZone: fm.ID(dst.to), Traffic: nativeTraffic(t, "192.0.2.10", "198.51.100.20", 443)}
			for _, offset := range []time.Duration{0, time.Hour, 9 * time.Hour, 7*24*time.Hour + time.Hour, 364*24*time.Hour + time.Hour} {
				q.At = at.Add(offset)
				answer, err := (policy.Engine{}).Query(t.Context(), observed, q)
				want := offset == time.Hour || offset == 7*24*time.Hour+time.Hour || offset == 364*24*time.Hour+time.Hour
				if err != nil || !answer.Complete || (!answer.Allowed.Empty()) != want {
					t.Fatalf("schedule at %v: %+v %v", q.At, answer, err)
				}
			}
			unknown, _ := scheduleCapture(t, dst.vendor, dst.version, raw, false)
			if _, err := p.Verify(t.Context(), unknown); err == nil {
				t.Fatal("unobserved calendar passed readback")
			}
		})
	}
}

func TestMigrationRejectsSubsetWithTimeVaryingSourceShadowing(t *testing.T) {
	fixtures := migrationFixtures(t)
	src := fixtures[len(fixtures)-1]
	weekly := "set schedule office schedule-type recurring weekly monday 09:00-17:00\n"
	blocked := strings.Replace(src.scheduled("office", "client", "server", "https", "blocked"), "action allow", "action drop", 1)
	// The permit is effective off-hours only; selecting it alone must not turn
	// a Monday drop into a target permit. No synthesized approximation is safe.
	permit := src.native("client2", "server2", "https2", "allow")
	source, _ := scheduleCapture(t, src.vendor, src.version, src.topology+weekly+blocked+permit, true)
	target, clock := scheduleCapture(t, src.vendor, src.version, src.topology, true)
	if !source.Complete() {
		t.Fatal(source.Diagnostics())
	}
	var chain fm.PolicyChain
	for r := range source.DeclaredRules() {
		if r.Name() == "allow" {
			chain = r.Chain()
		}
	}
	request := analysis.MigrationRequest{At: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), Clock: &clock, Zones: map[fm.ID]fm.ID{"inside": "inside", "outside": "outside"}, Chains: map[fm.PolicyChain]fm.PolicyChain{chain: chain}, Pairs: []analysis.ZonePair{{From: "inside", To: "outside"}}, Rules: []fm.ID{"allow"}}
	renderer, _ := vendors.Renderer(src.vendor)
	m := analysis.Migrator{Planner: plan.Planner{Renderer: renderer}}
	result, err := m.Plan(t.Context(), source, target, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan != nil || len(result.Issues) == 0 {
		t.Fatalf("time-varying omitted predecessor accepted: %+v", result)
	}
	request.Rules = nil
	result, err = m.Plan(t.Context(), source, target, request)
	if err != nil || result.Plan == nil {
		t.Fatalf("complete ordered selection rejected: %+v %v", result, err)
	}
	if _, err := result.Plan.Verify(t.Context(), result.Plan.After()); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationFortyTwoDirectedPolicyPairs(t *testing.T) {
	fixtures := migrationFixtures(t)
	for _, src := range fixtures {
		for _, dst := range fixtures {
			if src.vendor == dst.vendor {
				continue
			}
			t.Run(src.vendor+"-to-"+dst.vendor, func(t *testing.T) {
				source := nativeParse(t, src.vendor, src.version, src.topology+src.native("client", "server", "https", "allow"))
				baseline := dst.topology
				if dst.vendor == "asa" {
					baseline += "access-list IN extended deny ip any4 any4\naccess-group IN in interface inside\n"
				}
				target := nativeParse(t, dst.vendor, dst.version, baseline)
				var sourceChain fm.PolicyChain
				var selected []fm.ID
				for r := range source.DeclaredRules() {
					if !r.Builtin() && r.Action() == fm.Permit {
						sourceChain = r.Chain()
						selected = append(selected, r.ID())
					}
				}
				targetChain := fm.PolicyChain{Scope: dst.scope, RuleSet: dst.chain}
				if dst.vendor == "paloalto" {
					for r := range target.OrderedRules() {
						targetChain = r.Chain()
						break
					}
				}
				renderer, _ := vendors.Renderer(dst.vendor)
				request := analysis.MigrationRequest{Zones: map[fm.ID]fm.ID{fm.ID(src.from): fm.ID(dst.from), fm.ID(src.to): fm.ID(dst.to)}, Chains: map[fm.PolicyChain]fm.PolicyChain{sourceChain: targetChain}, Pairs: []analysis.ZonePair{{From: fm.ID(src.from), To: fm.ID(src.to)}}, Rules: selected}
				if dst.vendor == "asa" {
					request.Zones[fm.ID(src.to)] = ""
				}
				result, err := (analysis.Migrator{Planner: plan.Planner{Renderer: renderer}}).Plan(t.Context(), source, target, request)
				if err != nil {
					t.Fatal(err)
				}
				if result.Plan == nil {
					t.Fatalf("migration rejected: %+v", result.Issues)
				}
				p := result.Plan
				if len(p.Changes()) != 1 {
					t.Fatalf("expected one exact HTTPS rule: %+v", p.Changes())
				}
				r := p.After().Rule(p.Changes()[0].Rule).Record()
				client := p.After().Address(r.Match.Sources[0].ID).Name()
				server := p.After().Address(r.Match.Destinations[0].ID).Name()
				web := p.After().Service(r.Match.Services[0].ID).Name()
				observed := nativeParse(t, dst.vendor, dst.version, dst.topology+dst.native(client, server, web, r.Name))
				if dst.vendor == "asa" {
					observed = nativeParse(t, dst.vendor, dst.version, dst.topology+dst.native(client, server, web, r.Name)+"access-list IN extended deny ip any4 any4\n")
				}
				if _, err := p.Verify(t.Context(), observed); err != nil {
					t.Fatalf("independent target capture: %v\nexpected: %+v\nactual: %+v\nexpected svc: %+v\nactual svc: %+v", err, p.After().Export().Rules, observed.Export().Rules, p.After().Export().Services, observed.Export().Services)
				}
				q := policy.Request{Scope: targetChain.Scope, RuleSet: targetChain.RuleSet, FromZone: fm.ID(dst.from), ToZone: fm.ID(dst.to), Traffic: nativeTraffic(t, "192.0.2.10", "198.51.100.20", 443)}
				answer, err := (policy.Engine{}).Query(t.Context(), observed, q)
				if err != nil || answer.Allowed.Empty() {
					t.Fatalf("HTTPS intent lost: %+v %v", answer, err)
				}
				q.Traffic = nativeTraffic(t, "192.0.2.10", "198.51.100.20", 444)
				answer, err = (policy.Engine{}).Query(t.Context(), observed, q)
				if err != nil || !answer.Allowed.Empty() {
					t.Fatalf("migration widened service: %+v %v", answer, err)
				}
			})
		}
	}
}
