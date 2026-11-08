package vendors_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
)

func natMigrationFixture(t *testing.T, vendor string) migrationFixture {
	t.Helper()
	for _, fixture := range migrationFixtures(t) {
		if fixture.vendor == vendor {
			return fixture
		}
	}
	t.Fatalf("missing migration fixture: %s", vendor)
	return migrationFixture{}
}

// These captures are authored for a fixed, explicit wire domain. Names are the
// only data borrowed from the candidate; command output is never replayed.
func sourcePoolCapture(f migrationFixture, pat bool, name, pool, set, client, server, service string) string {
	switch f.vendor {
	case "paloalto":
		mode := "dynamic-ip"
		if pat {
			mode = "dynamic-ip-and-port"
		}
		return fmt.Sprintf(`set address %s ip-netmask 192.0.2.10/32
set address %s ip-netmask 198.51.100.20/32
set service %s protocol tcp source-port 0-65535
set service %s protocol tcp port 443
set rulebase nat rules %s from inside
set rulebase nat rules %s to outside
set rulebase nat rules %s source %s
set rulebase nat rules %s destination %s
set rulebase nat rules %s service %s
set rulebase nat rules %s source-translation %s translated-address [ 203.0.113.100-203.0.113.103 ]
`, client, server, service, service, name, name, name, client, name, server, name, service, name, mode)
	case "huawei":
		mode := "no-pat global"
		if pat {
			mode = "pat"
		}
		return fmt.Sprintf(`nat address-group %s
 mode %s
 section 0 203.0.113.100 203.0.113.103
#
nat-policy
 rule name %s
  source-zone trust
  destination-zone untrust
  source-address 192.0.2.10 mask 32
  destination-address 198.51.100.20 mask 32
  service protocol tcp source-port 0 to 65535 destination-port 443
  action source-nat address-group %s
#
`, pool, mode, name, pool)
	case "srx":
		ports := fmt.Sprintf("set security nat source pool %s port no-translation\n", pool)
		if pat {
			ports = ""
		}
		return fmt.Sprintf(`set security nat source pool %s address 203.0.113.100 to 203.0.113.103
%sset security nat source rule-set %s from zone inside
set security nat source rule-set %s to zone outside
set security nat source rule-set %s rule %s match source-address 192.0.2.10/32
set security nat source rule-set %s rule %s match destination-address 198.51.100.20/32
set security nat source rule-set %s rule %s match protocol tcp
set security nat source rule-set %s rule %s match destination-port 443
set security nat source rule-set %s rule %s then source-nat pool %s
`, pool, ports, set, set, set, name, set, name, set, name, set, name, set, name, pool)
	}
	return ""
}

func natMigrationInput(t *testing.T, source, target *fm.Firewall, src, dst migrationFixture) plan.MigrationInput {
	t.Helper()
	chain := fm.PolicyChain{Scope: src.scope, RuleSet: src.chain}
	for r := range source.DeclaredRules() {
		if !r.Builtin() {
			chain = r.Chain()
			break
		}
	}
	input := plan.MigrationInput{From: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		Contexts: []plan.MigrationContextMapping{{Source: plan.MigrationContext{Chain: chain, FromZone: fm.ID(src.from), ToZone: fm.ID(src.to)},
			Target: plan.MigrationContext{Chain: fm.PolicyChain{Scope: dst.scope, RuleSet: dst.chain}, FromZone: fm.ID(dst.from), ToZone: fm.ID(dst.to)}}},
		VRFs: []plan.MigrationVRFMapping{{Source: "", Target: ""}}}
	for _, n := range source.DynamicNATs() {
		input.DynamicNATs = append(input.DynamicNATs, n.ID())
	}
	for _, n := range source.StaticNATs() {
		input.StaticNATs = append(input.StaticNATs, n.ID())
	}
	for _, pair := range [][2]string{{src.from, dst.from}, {src.to, dst.to}} {
		var a, b fm.ID
		for _, iface := range source.Interfaces() {
			if iface.Zone() != nil && iface.Zone().ID() == fm.ID(pair[0]) {
				a = iface.ID()
			}
		}
		for _, iface := range target.Interfaces() {
			if iface.Zone() != nil && iface.Zone().ID() == fm.ID(pair[1]) {
				b = iface.ID()
			}
		}
		if a == "" || b == "" {
			t.Fatal("fixture lacks explicit interface mapping")
		}
		input.Interfaces = append(input.Interfaces, plan.MigrationInterfaceMapping{Source: a, Target: b})
	}
	return input
}

func TestMigrationNativeSourcePoolsAcrossVendors(t *testing.T) {
	for _, tc := range []struct {
		source, target string
		pat            bool
	}{
		{"paloalto", "huawei", true}, {"huawei", "paloalto", true},
		{"paloalto", "huawei", false}, {"huawei", "paloalto", false},
		{"srx", "paloalto", false}, {"srx", "huawei", false},
		{"paloalto", "srx", false}, {"huawei", "srx", false},
	} {
		t.Run(fmt.Sprintf("%s-to-%s-pat=%v", tc.source, tc.target, tc.pat), func(t *testing.T) {
			src, dst := natMigrationFixture(t, tc.source), natMigrationFixture(t, tc.target)
			sourceRaw := src.topology + src.native("client", "server", "https", "allow") + sourcePoolCapture(src, tc.pat, "translate", "outbound", "selected", "nat-client", "nat-server", "nat-https")
			source := nativeParse(t, src.vendor, src.version, sourceRaw)
			target := nativeParse(t, dst.vendor, dst.version, dst.topology)
			input := natMigrationInput(t, source, target, src, dst)
			renderer, _ := vendors.Renderer(dst.vendor)
			planner := plan.Planner{Renderer: renderer}
			p, err := planner.Migrate(t.Context(), source, target, input)
			if err != nil {
				t.Fatal(err)
			}
			if p.NATProof() == nil || len(p.Commands()) == 0 || len(p.NativeChanges().Additions.DynamicNATs) != 1 {
				t.Fatal("migration omitted its native translation proof")
			}
			after := p.After()
			policyRule := after.Rule(p.Changes()[0].Rule).Record()
			client, server, service := after.Address(policyRule.Match.Sources[0].ID).Name(), after.Address(policyRule.Match.Destinations[0].ID).Name(), after.Service(policyRule.Match.Services[0].ID).Name()
			rule := p.NativeChanges().Additions.DynamicNATs[0]
			pool := after.NATPool(rule.SourcePool).Name()
			set := strings.TrimPrefix(rule.Order.Section, "source:")
			natClient, natServer, natService := "", "", ""
			if dst.vendor == "paloalto" {
				natClient, natServer, natService = after.Address(rule.Match.Sources[0].ID).Name(), after.Address(rule.Match.Destinations[0].ID).Name(), after.Service(rule.Match.Services[0].ID).Name()
			}
			raw := dst.topology + dst.native(client, server, service, policyRule.Name) + sourcePoolCapture(dst, tc.pat, rule.Name, pool, set, natClient, natServer, natService)
			observed := nativeParse(t, dst.vendor, dst.version, raw)
			if _, err := p.Verify(t.Context(), observed); err != nil {
				t.Fatalf("independent native capture: %v", err)
			}
			for _, changed := range []string{
				strings.ReplaceAll(raw, "203.0.113.103", "203.0.113.104"),
				strings.ReplaceAll(raw, "203.0.113.100", "203.0.113.101"),
			} {
				if _, err := p.Verify(t.Context(), nativeParse(t, dst.vendor, dst.version, changed)); err == nil {
					t.Fatal("changed allocation pool passed independent readback")
				}
			}
			input.Interfaces = nil
			if unsafe, err := planner.Migrate(t.Context(), source, target, input); err == nil || unsafe != nil {
				t.Fatal("missing interface mapping authorized migration")
			}
		})
	}
}

func TestMigrationNativeCompilerRefusesPATDomainChanges(t *testing.T) {
	for _, pair := range [][2]string{{"srx", "paloalto"}, {"srx", "huawei"}, {"paloalto", "srx"}, {"huawei", "srx"}, {"paloalto", "asa"}, {"paloalto", "hillstone"}, {"paloalto", "fortinet"}, {"paloalto", "netscreen"}} {
		t.Run(pair[0]+"-to-"+pair[1], func(t *testing.T) {
			src, dst := natMigrationFixture(t, pair[0]), natMigrationFixture(t, pair[1])
			source := nativeParse(t, src.vendor, src.version, src.topology+src.native("client", "server", "https", "allow")+sourcePoolCapture(src, true, "translate", "outbound", "selected", "nat-client", "nat-server", "nat-https"))
			target := nativeParse(t, dst.vendor, dst.version, dst.topology)
			input := natMigrationInput(t, source, target, src, dst)
			compiler := vendors.MigrationCompiler{}
			changes, err := compiler.CompileMigrationNAT(t.Context(), source, target, plan.NativeMigrationDraft{Input: input})
			var issue *plan.MigrationError
			if !errors.As(err, &issue) || len(changes.Additions.DynamicNATs)+len(changes.Additions.NATPools) != 0 {
				t.Fatal("unsafe allocation domain returned a partial delta", changes, err)
			}
			if (src.vendor == "srx" || dst.vendor == "srx") && issue.Issue.Code != "pat-port-domain" {
				t.Fatal("translated port-domain difference was not explicit", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := compiler.CompileMigrationNAT(ctx, source, target, plan.NativeMigrationDraft{Input: input}); !errors.Is(err, context.Canceled) {
				t.Fatal("compiler lost cancellation", err)
			}
			if _, err := compiler.CompileMigrationNAT(t.Context(), source, target, plan.NativeMigrationDraft{Input: input, Limits: policy.Limits{MaxVisits: 1}}); !errors.Is(err, policy.ErrBudget) {
				t.Fatal("compiler exceeded ingress budget", err)
			}
		})
	}
}

func ownedPoolCapture(f migrationFixture, client, server, service, rule, pool string) string {
	policy := f.native(client, server, service, rule)
	if f.vendor == "fortinet" {
		policy = strings.Replace(policy, "set logtraffic disable\n", "set logtraffic disable\nset nat enable\nset ippool enable\nset poolname "+pool+"\n", 1)
		return "config firewall ippool\nedit " + pool + "\nset type overload\nset startip 203.0.113.100\nset endip 203.0.113.103\nnext\nend\n" + policy
	}
	policy = strings.Replace(policy, service+" permit", service+" nat src dip-id "+pool+" permit", 1)
	return "set interface ethernet0/2 dip " + pool + " 203.0.113.100 203.0.113.103\n" + policy
}

func TestMigrationNativePolicyOwners(t *testing.T) {
	for _, pair := range [][2]string{{"fortinet", "fortinet"}, {"netscreen", "netscreen"}, {"fortinet", "paloalto"}, {"fortinet", "huawei"}} {
		t.Run(pair[0]+"-to-"+pair[1], func(t *testing.T) {
			src, dst := natMigrationFixture(t, pair[0]), natMigrationFixture(t, pair[1])
			poolName := "outbound"
			if src.vendor == "netscreen" {
				poolName = "4"
			}
			source := nativeParse(t, src.vendor, src.version, src.topology+ownedPoolCapture(src, "client", "server", "https", "allow", poolName))
			target := nativeParse(t, dst.vendor, dst.version, dst.topology)
			input := natMigrationInput(t, source, target, src, dst)
			renderer, _ := vendors.Renderer(dst.vendor)
			p, err := (plan.Planner{Renderer: renderer}).Migrate(t.Context(), source, target, input)
			if err != nil {
				t.Fatal(err)
			}
			after := p.After()
			rule := after.Rule(p.Changes()[0].Rule).Record()
			client, server, service := after.Address(rule.Match.Sources[0].ID).Name(), after.Address(rule.Match.Destinations[0].ID).Name(), after.Service(rule.Match.Services[0].ID).Name()
			nat := p.NativeChanges().Additions.DynamicNATs[0]
			pool := after.NATPool(nat.SourcePool).Name()
			var capture string
			if dst.vendor == "fortinet" || dst.vendor == "netscreen" {
				if nat.Rule != rule.ID {
					t.Fatal("NAT is not attached to the new owner")
				}
				capture = dst.topology + ownedPoolCapture(dst, client, server, service, rule.Name, pool)
			} else {
				natClient, natServer, natService := "", "", ""
				if dst.vendor == "paloalto" {
					natClient, natServer, natService = after.Address(nat.Match.Sources[0].ID).Name(), after.Address(nat.Match.Destinations[0].ID).Name(), after.Service(nat.Match.Services[0].ID).Name()
				}
				capture = dst.topology + dst.native(client, server, service, rule.Name) + sourcePoolCapture(dst, true, nat.Name, pool, "", natClient, natServer, natService)
			}
			if _, err := p.Verify(t.Context(), nativeParse(t, dst.vendor, dst.version, capture)); err != nil {
				t.Fatal("independent policy-owned capture", err)
			}
		})
	}
}

func destinationCapture(f migrationFixture, name, pool, set, client, server, service string) string {
	switch f.vendor {
	case "paloalto":
		text := sourcePoolCapture(f, false, name, "", "", client, server, service)
		text = strings.ReplaceAll(text, "set rulebase nat rules "+name+" source-translation dynamic-ip translated-address [ 203.0.113.100-203.0.113.103 ]\n", "")
		return text + "set rulebase nat rules " + name + " destination-translation translated-address 198.51.100.30\nset rulebase nat rules " + name + " destination-translation translated-port 8443\n"
	case "huawei":
		return fmt.Sprintf(`destination-nat address-group %s
 section 0 198.51.100.30
#
nat-policy
 rule name %s
  source-zone trust
  destination-zone untrust
  source-address 192.0.2.10 mask 32
  destination-address 198.51.100.20 mask 32
  service protocol tcp source-port 0 to 65535 destination-port 443
  action destination-nat address-group %s 8443
#
`, pool, name, pool)
	case "srx":
		return fmt.Sprintf(`set security nat destination pool %s address 198.51.100.30/32
set security nat destination pool %s address port 8443
set security nat destination rule-set %s from zone inside
set security nat destination rule-set %s rule %s match source-address 192.0.2.10/32
set security nat destination rule-set %s rule %s match destination-address 198.51.100.20/32
set security nat destination rule-set %s rule %s match protocol tcp
set security nat destination rule-set %s rule %s match destination-port 443
set security nat destination rule-set %s rule %s then destination-nat pool %s
`, pool, pool, set, set, name, set, name, set, name, set, name, set, name, pool)
	}
	return ""
}

func TestMigrationCompilerNativeDestinationRelations(t *testing.T) {
	for _, pair := range [][2]string{{"paloalto", "huawei"}, {"huawei", "paloalto"}, {"srx", "paloalto"}, {"srx", "huawei"}, {"srx", "srx"}} {
		t.Run(pair[0]+"-to-"+pair[1], func(t *testing.T) {
			src, dst := natMigrationFixture(t, pair[0]), natMigrationFixture(t, pair[1])
			source := nativeParse(t, src.vendor, src.version, src.topology+destinationCapture(src, "translate", "backend", "selected", "client", "server", "https"))
			target := nativeParse(t, dst.vendor, dst.version, dst.topology)
			input := natMigrationInput(t, source, target, src, dst)
			changes, err := (vendors.MigrationCompiler{}).CompileMigrationNAT(t.Context(), source, target, plan.NativeMigrationDraft{Input: input})
			if err != nil {
				t.Fatal(err)
			}
			if len(changes.Additions.DynamicNATs) != 1 {
				t.Fatal("compiler did not emit one destination relation")
			}
			r := changes.Additions.DynamicNATs[0]
			pool, set := "", strings.TrimPrefix(r.Order.Section, "destination:")
			if len(changes.Additions.NATPools) > 0 {
				pool = changes.Additions.NATPools[0].Name
			}
			client, server, service := "", "", ""
			if dst.vendor == "paloalto" {
				client, server, service = string(r.Match.Sources[0].ID), string(r.Match.Destinations[0].ID), string(r.Match.Services[0].ID)
			}
			capture := dst.topology + destinationCapture(dst, r.Name, pool, set, client, server, service)
			observed := nativeParse(t, dst.vendor, dst.version, capture)
			renderer, _ := vendors.Renderer(dst.vendor)
			commands, err := renderer.(plan.NativeRenderer).RenderNative(t.Context(), target, observed, changes)
			if err != nil || len(commands) == 0 {
				t.Fatal("compiler and independent native destination capture disagree", err)
			}
			q := policy.Request{FromZone: fm.ID(dst.from), ToZone: fm.ID(dst.to), Traffic: nativeTraffic(t, "192.0.2.10", "198.51.100.20", 443)}
			result, err := (policy.Engine{}).QueryNAT(t.Context(), observed, q)
			if err != nil || !result.Complete || len(result.Relations) != 1 || !result.Relations[0].Exact {
				t.Fatal("destination relation is not exact", result, err)
			}
			for _, box := range result.Relations[0].Translated.Regions() {
				if box.Destination.First.String() != "198.51.100.30" || box.Destination.Last != box.Destination.First || box.DestinationPort.Low != 8443 || box.DestinationPort.High != 8443 {
					t.Fatal("destination relation changed address or port", box)
				}
			}
		})
	}
}

func TestMigrationCompilerNativeStaticSource(t *testing.T) {
	f := natMigrationFixture(t, "paloalto")
	text := sourcePoolCapture(f, false, "translate", "", "", "client", "server", "https")
	text = strings.Replace(text, "source-translation dynamic-ip translated-address [ 203.0.113.100-203.0.113.103 ]", "source-translation static-ip translated-address 203.0.113.100/32", 1)
	text += "set rulebase nat rules translate source-translation static-ip bi-directional no\n"
	source := nativeParse(t, f.vendor, f.version, f.topology+text)
	target := nativeParse(t, f.vendor, f.version, f.topology)
	input := natMigrationInput(t, source, target, f, f)
	changes, err := (vendors.MigrationCompiler{}).CompileMigrationNAT(t.Context(), source, target, plan.NativeMigrationDraft{Input: input})
	if err != nil || len(changes.Additions.StaticNATs) != 1 || len(changes.Additions.DynamicNATs) != 0 {
		t.Fatal("fixed source relation lost its static object", changes, err)
	}
	r := changes.Additions.StaticNATs[0]
	text = strings.ReplaceAll(text, "nat rules translate ", "nat rules "+r.Name+" ")
	actual := strings.NewReplacer("client", string(r.Match.Sources[0].ID), "server", string(r.Match.Destinations[0].ID), "https", string(r.Match.Services[0].ID)).Replace(text)
	observed := nativeParse(t, f.vendor, f.version, f.topology+actual)
	renderer, _ := vendors.Renderer(f.vendor)
	if _, err := renderer.(plan.NativeRenderer).RenderNative(t.Context(), target, observed, changes); err != nil {
		t.Fatal("independent fixed source capture", err)
	}
	data := source.Export()
	data.StaticNATs[0].Bidirectional = true
	reverse, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	var issue *plan.MigrationError
	if c, err := (vendors.MigrationCompiler{}).CompileMigrationNAT(t.Context(), reverse, target, plan.NativeMigrationDraft{Input: input}); !errors.As(err, &issue) || len(c.Additions.StaticNATs) != 0 {
		t.Fatal("implicit reverse relation was silently dropped", c, err)
	}
}

func TestMigrationPANFixedAndDestinationRelations(t *testing.T) {
	f := natMigrationFixture(t, "paloalto")
	for _, kind := range []string{"static-source", "destination-port"} {
		t.Run(kind, func(t *testing.T) {
			declaration := destinationCapture(f, "translate", "", "", "nat-client", "nat-server", "nat-https")
			if kind == "static-source" {
				declaration = sourcePoolCapture(f, false, "translate", "", "", "nat-client", "nat-server", "nat-https")
				declaration = strings.Replace(declaration, "source-translation dynamic-ip translated-address [ 203.0.113.100-203.0.113.103 ]", "source-translation static-ip translated-address 203.0.113.100/32", 1)
				declaration += "set rulebase nat rules translate source-translation static-ip bi-directional no\n"
			}
			source := nativeParse(t, f.vendor, f.version, f.topology+f.native("client", "server", "https", "allow")+declaration)
			target := nativeParse(t, f.vendor, f.version, f.topology)
			input := natMigrationInput(t, source, target, f, f)
			renderer, _ := vendors.Renderer(f.vendor)
			p, err := (plan.Planner{Renderer: renderer}).Migrate(t.Context(), source, target, input)
			if err != nil {
				t.Fatal(err)
			}
			after := p.After()
			rule := after.Rule(p.Changes()[0].Rule).Record()
			client, server, service := after.Address(rule.Match.Sources[0].ID).Name(), after.Address(rule.Match.Destinations[0].ID).Name(), after.Service(rule.Match.Services[0].ID).Name()
			var name string
			var match fm.Match
			if kind == "static-source" {
				n := p.NativeChanges().Additions.StaticNATs[0]
				name, match = n.Name, n.Match
			} else {
				n := p.NativeChanges().Additions.DynamicNATs[0]
				name, match = n.Name, n.Match
			}
			declaration = strings.ReplaceAll(declaration, "nat rules translate ", "nat rules "+name+" ")
			declaration = strings.NewReplacer("nat-client", after.Address(match.Sources[0].ID).Name(), "nat-server", after.Address(match.Destinations[0].ID).Name(), "nat-https", after.Service(match.Services[0].ID).Name()).Replace(declaration)
			capture := f.topology + f.native(client, server, service, rule.Name) + declaration
			if _, err := p.Verify(t.Context(), nativeParse(t, f.vendor, f.version, capture)); err != nil {
				t.Fatal("independent fixed relation migration capture", err)
			}
		})
	}
}

func TestMigrationRejectsUnselectedAndExistingTranslationEffects(t *testing.T) {
	src, dst := natMigrationFixture(t, "paloalto"), natMigrationFixture(t, "huawei")
	policyText := src.native("client", "server", "https", "allow")
	renderer, _ := vendors.Renderer(dst.vendor)
	planner := plan.Planner{Renderer: renderer}
	t.Run("source-identity-target-existing-pat", func(t *testing.T) {
		source := nativeParse(t, src.vendor, src.version, src.topology+policyText)
		target := nativeParse(t, dst.vendor, dst.version, dst.topology+sourcePoolCapture(dst, true, "existing", "old-pool", "", "", "", ""))
		input := natMigrationInput(t, source, target, src, dst)
		if p, err := planner.Migrate(t.Context(), source, target, input); err == nil || p != nil {
			t.Fatal("target PAT was mistaken for source identity behavior", err)
		}
	})
	t.Run("selected-owner-does-not-authorize-second-policy", func(t *testing.T) {
		other := strings.ReplaceAll(src.native("other", "other-server", "other-web", "allow-b"), "192.0.2.10/32", "192.0.2.11/32")
		nat := sourcePoolCapture(src, true, "shared", "", "", "nat-client", "nat-server", "nat-https")
		nat = strings.ReplaceAll(nat, "192.0.2.10/32", "192.0.2.10/31")
		source := nativeParse(t, src.vendor, src.version, src.topology+policyText+other+nat)
		target := nativeParse(t, dst.vendor, dst.version, dst.topology)
		input := natMigrationInput(t, source, target, src, dst)
		input.Rules = []fm.ID{"allow"}
		if p, err := planner.Migrate(t.Context(), source, target, input); err == nil || p != nil {
			t.Fatal("one selected policy authorized translation of an unselected policy", err)
		}
	})
}

func interfaceCapture(f migrationFixture, name, client, server, service string) string {
	text := sourcePoolCapture(f, true, name, "outbound", "", client, server, service)
	if f.vendor == "paloalto" {
		return strings.Replace(text, "source-translation dynamic-ip-and-port translated-address [ 203.0.113.100-203.0.113.103 ]", "source-translation dynamic-ip-and-port interface-address interface ethernet1/2", 1)
	}
	text = text[strings.Index(text, "nat-policy\n"):]
	return strings.Replace(text, "  action source-nat address-group outbound", "  egress-interface GigabitEthernet1/0/2\n  action source-nat easy-ip", 1)
}

func TestMigrationNativeInterfaceAllocation(t *testing.T) {
	for _, pair := range [][2]string{{"paloalto", "huawei"}, {"huawei", "paloalto"}} {
		t.Run(pair[0]+"-to-"+pair[1], func(t *testing.T) {
			src, dst := natMigrationFixture(t, pair[0]), natMigrationFixture(t, pair[1])
			source := nativeParse(t, src.vendor, src.version, src.topology+src.native("client", "server", "https", "allow")+interfaceCapture(src, "translate", "nat-client", "nat-server", "nat-https"))
			target := nativeParse(t, dst.vendor, dst.version, dst.topology)
			input := natMigrationInput(t, source, target, src, dst)
			renderer, _ := vendors.Renderer(dst.vendor)
			planner := plan.Planner{Renderer: renderer}
			p, err := planner.Migrate(t.Context(), source, target, input)
			if err != nil {
				t.Fatal(err)
			}
			after := p.After()
			rule := after.Rule(p.Changes()[0].Rule).Record()
			client, server, service := after.Address(rule.Match.Sources[0].ID).Name(), after.Address(rule.Match.Destinations[0].ID).Name(), after.Service(rule.Match.Services[0].ID).Name()
			nat := p.NativeChanges().Additions.DynamicNATs[0]
			natClient, natServer, natService := "", "", ""
			if dst.vendor == "paloalto" {
				natClient, natServer, natService = after.Address(nat.Match.Sources[0].ID).Name(), after.Address(nat.Match.Destinations[0].ID).Name(), after.Service(nat.Match.Services[0].ID).Name()
			}
			capture := dst.topology + dst.native(client, server, service, rule.Name) + interfaceCapture(dst, nat.Name, natClient, natServer, natService)
			if _, err := p.Verify(t.Context(), nativeParse(t, dst.vendor, dst.version, capture)); err != nil {
				t.Fatal("independent interface allocation capture", err)
			}
			changed := nativeParse(t, dst.vendor, dst.version, strings.ReplaceAll(dst.topology, "198.51.100.1", "198.51.100.2"))
			if unsafe, err := planner.Migrate(t.Context(), source, changed, input); err == nil || unsafe != nil {
				t.Fatal("mapped interface changed the translated address")
			}
		})
	}
}
