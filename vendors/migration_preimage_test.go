package vendors_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors"
)

func TestHuaweiPortMigration(t *testing.T) {
	const vendor = "huawei"
	f := natMigrationFixture(t, vendor)
	policyText := strings.NewReplacer("198.51.100.20", "198.51.100.30", "443", "8443").Replace(f.native("client", "server", "web", "allow"))
	nat := destinationCapture(f, "translate", "backend", "selected", "nat-client", "nat-server", "nat-web")
	source := nativeParse(t, vendor, f.version, f.topology+policyText+nat)
	target := nativeParse(t, vendor, f.version, f.topology)
	input := natMigrationInput(t, source, target, f, f)
	for rule := range source.DeclaredRules() {
		if !rule.Builtin() {
			input.Rules = append(input.Rules, rule.ID())
		}
	}
	renderer, _ := vendors.Renderer(vendor)
	planner := plan.Planner{Renderer: renderer}
	p, err := planner.Migrate(t.Context(), source, target, input)
	if err != nil || p == nil || p.NATProof() == nil || !p.NATProof().IntentSatisfied {
		t.Fatal("native destination-port migration did not prove wire ownership", err)
	}
	after := p.After()
	rule := after.Rule(p.Changes()[0].Rule).Record()
	client := after.Address(rule.Match.Sources[0].ID).Name()
	server := after.Address(rule.Match.Destinations[0].ID).Name()
	service := after.Service(rule.Match.Services[0].ID).Name()
	declaration := strings.NewReplacer("198.51.100.20", "198.51.100.30", "443", "8443").Replace(f.native(client, server, service, rule.Name))
	n := p.NativeChanges().Additions.DynamicNATs[0]
	pool := after.NATPool(n.DestinationPool).Name()
	set := strings.TrimPrefix(n.Order.Section, "destination:")
	capture := f.topology + declaration + destinationCapture(f, n.Name, pool, set, "", "", "")
	if _, err := p.Verify(t.Context(), nativeParse(t, vendor, f.version, capture)); err != nil {
		t.Fatal("independent translated-port capture", err)
	}

	// The same translation must not be authorized for an unselected
	// source simply because both policies use the same real server.
	broader := strings.ReplaceAll(nat, "192.0.2.10/32", "192.0.2.10/31")
	broader = strings.ReplaceAll(broader, "192.0.2.10 mask 32", "192.0.2.10 mask 31")
	other := strings.ReplaceAll(strings.NewReplacer("198.51.100.20", "198.51.100.30", "443", "8443").Replace(f.native("other-client", "other-server", "other-web", "other")), "192.0.2.10", "192.0.2.11")
	source = nativeParse(t, vendor, f.version, f.topology+policyText+other+broader)
	input.StaticNATs, input.DynamicNATs = nil, nil
	for _, n := range source.DynamicNATs() {
		input.DynamicNATs = append(input.DynamicNATs, n.ID())
	}
	if unsafe, err := planner.Migrate(t.Context(), source, target, input); unsafe != nil || !errors.Is(err, policy.ErrNotEquivalent) {
		t.Fatal("unselected original source escaped outside-domain proof", err)
	}
}
