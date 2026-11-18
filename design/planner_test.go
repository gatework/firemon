package design_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
)

var now = time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func inline(s string) firemon.AddressRef {
	return firemon.InlineAddress(firemon.PrefixEntry(prefix(s)))
}

func lab(rules ...firemon.SecurityRule) *firemon.Config {
	return &firemon.Config{
		Vendor: firemon.VendorHillstone,
		Semantics: firemon.Semantics{
			PolicyDestination: firemon.AddressStageTranslated, IntrazoneAction: firemon.ActionDeny,
			InterzoneAction: firemon.ActionDeny, DefaultVirtualRouter: "vr", NumericRuleIDs: true,
		},
		VirtualRouters: []firemon.VirtualRouter{{Name: "vr"}},
		Zones:          []firemon.Zone{{Name: "trust"}, {Name: "dmz"}, {Name: "untrust"}},
		Interfaces: []firemon.Interface{
			{Name: "e0", Zone: "untrust", VirtualRouter: "vr", Addresses: []netip.Prefix{prefix("203.0.113.2/30")}},
			{Name: "e1", Zone: "trust", VirtualRouter: "vr", Addresses: []netip.Prefix{prefix("10.0.0.1/16")}},
			{Name: "e2", Zone: "dmz", VirtualRouter: "vr", Addresses: []netip.Prefix{prefix("172.16.0.1/24")}},
		},
		Routes: []firemon.Route{{VirtualRouter: "vr", Destination: prefix("0.0.0.0/0"), NextHop: netip.MustParseAddr("203.0.113.1")}},
		Addresses: []firemon.Address{
			{Name: "web", Entries: []firemon.AddressEntry{firemon.HostEntry(netip.MustParseAddr("172.16.0.10"))}},
			{Name: "ops", Entries: []firemon.AddressEntry{firemon.PrefixEntry(prefix("10.0.1.0/24"))}},
		},
		Services: []firemon.Service{{Name: "HTTPS", Predefined: true, Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(443))}}},
		Rules:    rules,
	}
}

func rule(id string, action firemon.Action, from, to string, src, dst []firemon.AddressRef, services ...string) firemon.SecurityRule {
	r := firemon.SecurityRule{ID: id, Action: action, Source: src, Destination: dst, Services: services}
	if from != "" {
		r.From = []string{from}
	}
	if to != "" {
		r.To = []string{to}
	}
	return r
}

func intent(t *testing.T, src, dst, svc string) design.Intent {
	t.Helper()
	s, err1 := traffic.ParseAddressSet(src)
	d, err2 := traffic.ParseAddressSet(dst)
	v, err3 := traffic.ParseServiceSet(svc)
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatal(err1, err2, err3)
	}
	return design.Intent{Src: s, Dst: d, Service: v, Name: "req"}
}

func plan(t *testing.T, cfg *firemon.Config, in design.Intent) *design.Plan {
	t.Helper()
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := design.New(fw, design.Options{Now: func() time.Time { return now }}).Plan(in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func describe(changes []design.Change) []string {
	out := make([]string, len(changes))
	for i, c := range changes {
		out[i] = c.String()
	}
	return out
}

func TestPlanner_Plan(t *testing.T) {
	t.Parallel()
	permitWeb := rule("5", firemon.ActionPermit, "trust", "dmz", []firemon.AddressRef{firemon.NamedAddress("ops")}, []firemon.AddressRef{firemon.NamedAddress("web")}, "HTTPS")
	tests := []struct {
		name    string
		cfg     *firemon.Config
		in      design.Intent
		status  design.Status
		changes []string
	}{
		{
			name: "already permitted", cfg: lab(permitWeb),
			in: intent(t, "10.0.1.9", "172.16.0.10", "tcp/443"), status: design.StatusNoChange,
		},
		{
			name: "new rule reuses objects", cfg: lab(),
			in: intent(t, "10.0.1.0/24", "172.16.0.10", "tcp/443"), status: design.StatusChange,
			changes: []string{"add rule 1 at end"},
		},
		{
			name: "new rule creates missing objects", cfg: lab(),
			in: intent(t, "10.0.2.5", "172.16.0.0/28", "tcp/8443"), status: design.StatusChange,
			changes: []string{"add address Host_10.0.2.5 10.0.2.5", "add address Net_172.16.0.0_28 172.16.0.0/28", "add service TCP_8443 tcp/8443", "add rule 1 at end"},
		},
		{
			name: "extend the source of a matching rule", cfg: lab(permitWeb),
			in: intent(t, "10.0.2.5", "172.16.0.10", "tcp/443"), status: design.StatusChange,
			changes: []string{"add address Host_10.0.2.5 10.0.2.5", "extend rule 5 source += Host_10.0.2.5"},
		},
		{
			name: "do not extend a rule wider than the intent",
			cfg:  lab(rule("5", firemon.ActionPermit, "trust", "dmz", []firemon.AddressRef{firemon.NamedAddress("ops")}, nil, "HTTPS")),
			in:   intent(t, "10.0.2.5", "172.16.0.10", "tcp/443"), status: design.StatusChange,
			changes: []string{"add address Host_10.0.2.5 10.0.2.5", "add rule 6 at end"},
		},
		{
			name: "place before a catch-all deny",
			cfg:  lab(permitWeb, rule("99", firemon.ActionDeny, "", "", nil, nil)),
			in:   intent(t, "10.0.3.0/24", "172.16.0.20", "tcp/22"), status: design.StatusChange,
			changes: []string{"add address Net_10.0.3.0_24 10.0.3.0/24", "add address Host_172.16.0.20 172.16.0.20", "add service TCP_22 tcp/22", "add rule 100 before 99"},
		},
		{
			name: "specific deny is a conflict",
			cfg:  lab(rule("3", firemon.ActionDeny, "", "", []firemon.AddressRef{inline("10.0.2.5/32")}, nil)),
			in:   intent(t, "10.0.2.4-10.0.2.5", "172.16.0.10", "tcp/443"), status: design.StatusConflict,
			changes: []string{"add address Host_10.0.2.4 10.0.2.4", "add rule 4 at end"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := plan(t, tt.cfg, tt.in)
			if p.Status != tt.status || !p.Verified {
				t.Fatalf("status %s verified=%v, want %s; changes %v unknown %v", p.Status, p.Verified, tt.status, describe(p.Changes), p.Unknown)
			}
			if got := describe(p.Changes); !slices.Equal(got, tt.changes) {
				t.Fatalf("changes:\n got %v\nwant %v", got, tt.changes)
			}
		})
	}
}

func TestPlanner_Override(t *testing.T) {
	t.Parallel()
	cfg := lab(rule("3", firemon.ActionDeny, "", "", []firemon.AddressRef{inline("10.0.2.5/32")}, nil))
	in := intent(t, "10.0.2.5", "172.16.0.10", "tcp/443")
	in.Override = true
	p := plan(t, cfg, in)
	if p.Status != design.StatusChange || !p.Verified {
		t.Fatalf("status %s verified=%v", p.Status, p.Verified)
	}
	last := p.Changes[len(p.Changes)-1].(design.AddRule)
	if last.Before != "3" || !strings.HasPrefix(last.Rule.Name, "req") {
		t.Fatalf("rule %+v", last)
	}
}

func TestApply_UnknownRule(t *testing.T) {
	t.Parallel()
	err := design.Apply(lab(), []design.Change{design.ExtendRule{RuleID: "nope", Field: design.FieldSource, Names: []string{"x"}}})
	if err == nil {
		t.Fatal("want error")
	}
}
