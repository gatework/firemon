package audit_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/audit"
	"github.com/gatework/firemon/traffic"
)

var now = time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)

func inline(s string) []firemon.AddressRef {
	return []firemon.AddressRef{firemon.InlineAddress(firemon.PrefixEntry(netip.MustParsePrefix(s)))}
}

func rule(id string, action firemon.Action, from, to []string, src, dst string, services ...string) firemon.SecurityRule {
	r := firemon.SecurityRule{ID: id, Action: action, From: from, To: to, Services: services}
	if src != "" {
		r.Source = inline(src)
	}
	if dst != "" {
		r.Destination = inline(dst)
	}
	return r
}

func TestRun(t *testing.T) {
	t.Parallel()
	p, d := firemon.ActionPermit, firemon.ActionDeny
	trust, dmz := []string{"trust"}, []string{"dmz"}
	expired := rule("9", p, nil, nil, "10.9.0.0/16", "")
	expired.Window = firemon.TimeWindow{End: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	disabled := rule("10", p, nil, nil, "10.10.0.0/16", "")
	disabled.Disabled = true
	cfg := &firemon.Config{
		Vendor: firemon.VendorPaloAlto,
		Zones:  []firemon.Zone{{Name: "trust"}, {Name: "dmz"}},
		Addresses: []firemon.Address{
			{Name: "used", Entries: []firemon.AddressEntry{firemon.PrefixEntry(netip.MustParsePrefix("10.5.0.0/16"))}},
			{Name: "orphan", Entries: []firemon.AddressEntry{firemon.PrefixEntry(netip.MustParsePrefix("10.6.0.0/16"))}},
		},
		Services: []firemon.Service{
			{Name: "https", Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(443))}},
			{Name: "ssh", Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(22))}},
		},
		Rules: []firemon.SecurityRule{
			rule("1", p, trust, dmz, "10.0.0.0/16", "172.16.0.0/24", "https"),
			rule("2", p, trust, dmz, "10.0.1.0/24", "172.16.0.10/32", "https"), // redundant with 1
			rule("3", d, nil, nil, "10.0.2.0/24", ""),                          // reachable: other services and zones
			rule("4", d, trust, dmz, "10.0.0.0/24", "172.16.0.0/24", "https"),  // shadowed by permit 1
			rule("5", p, nil, dmz, "10.0.0.0/16", "172.16.0.0/24", "https"),    // reachable: other source zones
			rule("6", p, trust, dmz, "10.0.0.0/16", "172.16.0.0/24"),           // reachable: other services
			{ID: "7", Action: p, Source: []firemon.AddressRef{firemon.NamedAddress("used")}},
			{ID: "8", Action: p}, // permit any
			expired, disabled,
		},
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := audit.Run(fw, audit.Options{Now: func() time.Time { return now }})
	want := map[audit.Kind][]string{
		audit.KindRedundant:     {"2"},
		audit.KindShadowed:      {"4"},
		audit.KindPermitAny:     {"8"},
		audit.KindExpired:       {"9"},
		audit.KindDisabled:      {"10"},
		audit.KindUnusedAddress: {"orphan"},
		audit.KindUnusedService: {"ssh"},
	}
	for kind, ids := range want {
		var got []string
		for _, f := range r.Of(kind) {
			got = append(got, f.Rule+f.Object)
		}
		if !slices.Equal(got, ids) {
			t.Errorf("%s: got %v, want %v", kind, got, ids)
		}
	}
	if by := r.Of(audit.KindShadowed)[0].By; !slices.Equal(by, []string{"1"}) {
		t.Errorf("shadowed by %v", by)
	}
}
