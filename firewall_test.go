package firemon_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/traffic"
)

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func sampleConfig() *firemon.Config {
	return &firemon.Config{
		Vendor:         firemon.VendorHillstone,
		Hostname:       "fw1",
		Semantics:      firemon.Semantics{InterzoneAction: firemon.ActionDeny, IntrazoneAction: firemon.ActionDeny, DefaultVirtualRouter: "trust-vr"},
		VirtualRouters: []firemon.VirtualRouter{{Name: "trust-vr"}},
		Zones:          []firemon.Zone{{Name: "trust", VirtualRouter: "trust-vr"}, {Name: "untrust", VirtualRouter: "trust-vr"}},
		Interfaces: []firemon.Interface{
			{Name: "eth0/0", Zone: "untrust", VirtualRouter: "trust-vr", Addresses: []netip.Prefix{mustPrefix("203.0.113.2/30")}},
			{Name: "eth0/1", Zone: "trust", VirtualRouter: "trust-vr", Addresses: []netip.Prefix{mustPrefix("10.0.0.1/24")}},
		},
		Routes: []firemon.Route{
			{VirtualRouter: "trust-vr", Destination: mustPrefix("0.0.0.0/0"), NextHop: netip.MustParseAddr("203.0.113.1")},
			{VirtualRouter: "trust-vr", Destination: mustPrefix("10.0.0.0/8"), NextHop: netip.MustParseAddr("10.0.0.254")},
		},
		Addresses: []firemon.Address{
			{Name: "web", Entries: []firemon.AddressEntry{firemon.HostEntry(netip.MustParseAddr("10.0.0.10"))}},
			{Name: "lan", Entries: []firemon.AddressEntry{firemon.PrefixEntry(mustPrefix("10.0.0.0/16")), {Kind: firemon.AddressKindPrefix, Prefix: mustPrefix("10.0.9.0/24"), Exclude: true}}},
			{Name: "cdn", Entries: []firemon.AddressEntry{firemon.FQDNEntry("*.example.com")}},
		},
		AddressGroups: []firemon.AddressGroup{
			{Name: "loop-a", Members: []string{"loop-b"}},
			{Name: "loop-b", Members: []string{"loop-a"}},
		},
		Services: []firemon.Service{
			{Name: "HTTPS", Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(443))}, Predefined: true},
		},
		Schedules: []firemon.Schedule{{Name: "q4", Windows: []firemon.TimeWindow{{
			Start: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		}}}},
		Rules: []firemon.SecurityRule{
			{ID: "1", From: []string{"untrust"}, To: []string{"trust"}, Destination: []firemon.AddressRef{firemon.NamedAddress("web")}, Services: []string{"HTTPS"}, Action: firemon.ActionPermit},
			{ID: "2", Source: []firemon.AddressRef{firemon.NamedAddress("cdn")}, Action: firemon.ActionPermit},
			{ID: "3", Source: []firemon.AddressRef{firemon.NamedAddress("loop-a")}, Action: firemon.ActionDeny},
			{ID: "4", Source: []firemon.AddressRef{firemon.NamedAddress("lan")}, Schedule: "q4", Action: firemon.ActionPermit},
		},
		StaticNATs: []firemon.StaticNAT{{
			ID: "1", Real: firemon.InlineAddress(firemon.RangeEntry(netip.MustParseAddr("10.0.0.10"), netip.MustParseAddr("10.0.0.13"))),
			Mapped: firemon.InlineAddress(firemon.PrefixEntry(mustPrefix("198.51.100.4/30"))),
		}},
	}
}

func TestCompile(t *testing.T) {
	t.Parallel()
	fw, err := firemon.Compile(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	rules := fw.Rules()
	if !rules[0].Decidable() || rules[0].Match().String() != "any -> 10.0.0.10 tcp/443" {
		t.Errorf("rule 1: %s %v", rules[0].Match(), rules[0].Issues())
	}
	if rules[1].Decidable() || rules[2].Decidable() {
		t.Errorf("fqdn and cycle rules must be undecidable: %v / %v", rules[1].Issues(), rules[2].Issues())
	}
	if got := rules[3].Match().Src.String(); got != "10.0.0.0-10.0.8.255,10.0.10.0-10.0.255.255" {
		t.Errorf("exclude: got %s", got)
	}
	if !rules[3].ActiveAt(time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)) || rules[3].ActiveAt(time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("schedule window not honoured")
	}
	if !rules[0].Applies("untrust", "trust") || rules[0].Applies("trust", "untrust") {
		t.Error("zone pair not honoured")
	}
	names := []string{}
	for name := range fw.Addresses() {
		names = append(names, name)
	}
	if want := []string{"lan", "web"}; !slices.Equal(names, want) {
		t.Errorf("exact addresses: got %v, want %v", names, want)
	}
}

func TestRoutingTable_Lookup(t *testing.T) {
	t.Parallel()
	fw, err := firemon.Compile(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	table, ok := fw.RoutingTable("trust-vr")
	if !ok {
		t.Fatal("missing table")
	}
	dst, _ := traffic.ParseAddressSet("10.0.0.5, 10.9.0.0/16, 203.0.113.208")
	egress, unrouted := table.Lookup(dst)
	got := map[string]string{}
	for _, e := range egress {
		got[e.Addresses.String()] = e.Interface + "/" + e.Zone
	}
	want := map[string]string{"10.0.0.5": "eth0/1/trust", "10.9.0.0/16": "eth0/1/trust", "203.0.113.208": "eth0/0/untrust"}
	if len(got) != len(want) || !unrouted.IsEmpty() {
		t.Fatalf("got %v unrouted %s", got, unrouted)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
}

func TestStaticMapping(t *testing.T) {
	t.Parallel()
	fw, err := firemon.Compile(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	m := fw.StaticNATs()[0]
	if !m.Enabled() {
		t.Fatal(m.Issues())
	}
	in, _ := traffic.ParseAddressSet("10.0.0.11-10.0.0.12")
	if got := m.ToMapped(in).String(); got != "198.51.100.5-198.51.100.6" {
		t.Errorf("ToMapped: %s", got)
	}
	if got := m.ToReal(m.ToMapped(in)); !got.Equal(in) {
		t.Errorf("ToReal: %s", got)
	}
}

func TestConfig_CloneIsDeep(t *testing.T) {
	t.Parallel()
	cfg := sampleConfig()
	c := cfg.Clone()
	c.Rules[0].Services[0] = "changed"
	c.Addresses[0].Entries[0] = firemon.FQDNEntry("x")
	if cfg.Rules[0].Services[0] != "HTTPS" || cfg.Addresses[0].Entries[0].Kind != firemon.AddressKindPrefix {
		t.Fatal("clone shares memory with the original")
	}
}
