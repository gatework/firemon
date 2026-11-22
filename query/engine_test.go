package query_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
)

var at = time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func addrs(t *testing.T, s string) traffic.AddressSet {
	t.Helper()
	a, err := traffic.ParseAddressSet(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func svc(t *testing.T, s string) traffic.ServiceSet {
	t.Helper()
	v, err := traffic.ParseServiceSet(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func inline(s string) firemon.AddressRef {
	return firemon.InlineAddress(firemon.PrefixEntry(prefix(s)))
}

// lab is a three-zone firewall: trust 10.0.0.0/8, dmz 172.16.0.0/24,
// untrust default route.
func lab(stage firemon.AddressStage, rules ...firemon.SecurityRule) *firemon.Config {
	return &firemon.Config{
		Vendor: firemon.VendorHillstone,
		Semantics: firemon.Semantics{
			PolicyDestination: stage, IntrazoneAction: firemon.ActionPermit, InterzoneAction: firemon.ActionDeny,
			DefaultVirtualRouter: "vr",
		},
		VirtualRouters: []firemon.VirtualRouter{{Name: "vr"}},
		Zones:          []firemon.Zone{{Name: "trust"}, {Name: "dmz"}, {Name: "untrust"}},
		Interfaces: []firemon.Interface{
			{Name: "e0", Zone: "untrust", VirtualRouter: "vr", Addresses: []netip.Prefix{prefix("203.0.113.2/30")}},
			{Name: "e1", Zone: "trust", VirtualRouter: "vr", Addresses: []netip.Prefix{prefix("10.0.0.1/24")}},
			{Name: "e2", Zone: "dmz", VirtualRouter: "vr", Addresses: []netip.Prefix{prefix("172.16.0.1/24")}},
		},
		Routes: []firemon.Route{
			{VirtualRouter: "vr", Destination: prefix("0.0.0.0/0"), NextHop: netip.MustParseAddr("203.0.113.1")},
			{VirtualRouter: "vr", Destination: prefix("10.0.0.0/8"), NextHop: netip.MustParseAddr("10.0.0.254")},
		},
		Addresses: []firemon.Address{{Name: "cdn", Entries: []firemon.AddressEntry{firemon.FQDNEntry("cdn.example.com")}}},
		Services: []firemon.Service{
			{Name: "https", Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(443))}},
			{Name: "http", Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(80))}},
		},
		Schedules: []firemon.Schedule{{Name: "nights", Recurrences: []firemon.Recurrence{{Start: 20 * time.Hour, End: 6 * time.Hour}}}},
		Rules:     rules,
	}
}

func engine(t *testing.T, cfg *firemon.Config) *query.Engine {
	t.Helper()
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return query.New(fw, query.Options{Now: func() time.Time { return at }})
}

func permit(id string, from, to string, src, dst string, services ...string) firemon.SecurityRule {
	r := firemon.SecurityRule{ID: id, Action: firemon.ActionPermit, Services: services}
	if from != "" {
		r.From = []string{from}
	}
	if to != "" {
		r.To = []string{to}
	}
	if src != "" {
		r.Source = []firemon.AddressRef{inline(src)}
	}
	if dst != "" {
		r.Destination = []firemon.AddressRef{inline(dst)}
	}
	return r
}

func deny(id string, from, to string, src, dst string, services ...string) firemon.SecurityRule {
	r := permit(id, from, to, src, dst, services...)
	r.Action = firemon.ActionDeny
	return r
}

func TestEngine_Query(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		cfg      *firemon.Config
		src, dst string
		service  string
		want     query.Verdict
		paths    int
	}{
		{
			name: "permit covers request",
			cfg:  lab(firemon.AddressStageOriginal, permit("1", "trust", "dmz", "10.0.0.0/8", "172.16.0.10/32", "https")),
			src:  "10.0.0.0/24", dst: "172.16.0.10", service: "tcp/443", want: query.VerdictAllowed, paths: 1,
		},
		{
			name: "earlier deny shadows part of a permit",
			cfg: lab(firemon.AddressStageOriginal,
				deny("1", "", "", "10.0.0.5/32", ""),
				permit("2", "trust", "dmz", "10.0.0.0/8", "172.16.0.10/32", "https")),
			src: "10.0.0.0/24", dst: "172.16.0.10", service: "tcp/443", want: query.VerdictPartial, paths: 1,
		},
		{
			name: "no rule falls to interzone default",
			cfg:  lab(firemon.AddressStageOriginal),
			src:  "10.0.0.9", dst: "172.16.0.10", service: "tcp/22", want: query.VerdictDenied, paths: 1,
		},
		{
			name: "intrazone default permits",
			cfg:  lab(firemon.AddressStageOriginal),
			src:  "10.0.0.9", dst: "10.1.0.1", service: "tcp/22", want: query.VerdictAllowed, paths: 1,
		},
		{
			name: "zone pair mismatch does not match",
			cfg:  lab(firemon.AddressStageOriginal, permit("1", "dmz", "trust", "", "", "https")),
			src:  "10.0.0.9", dst: "172.16.0.10", service: "tcp/443", want: query.VerdictDenied, paths: 1,
		},
		{
			name: "undecidable rule before permit is indeterminate",
			cfg: lab(firemon.AddressStageOriginal,
				firemon.SecurityRule{ID: "1", Action: firemon.ActionDeny, Destination: []firemon.AddressRef{firemon.NamedAddress("cdn")}},
				permit("2", "", "", "", "", "https")),
			src: "10.0.0.9", dst: "172.16.0.10", service: "tcp/443", want: query.VerdictIndeterminate, paths: 1,
		},
		{
			name: "undecidable rule that cannot overlap is ignored",
			cfg: lab(firemon.AddressStageOriginal,
				firemon.SecurityRule{ID: "1", Action: firemon.ActionDeny, Source: []firemon.AddressRef{inline("192.0.2.0/24")}, Conditions: []firemon.Condition{firemon.ApplicationCondition("ssh")}},
				permit("2", "", "", "", "", "https")),
			src: "10.0.0.9", dst: "172.16.0.10", service: "tcp/443", want: query.VerdictAllowed, paths: 1,
		},
		{
			name: "routing splits destinations by zone",
			cfg:  lab(firemon.AddressStageOriginal, permit("1", "trust", "dmz", "", "", "https")),
			src:  "10.0.0.9", dst: "172.16.0.10,203.0.113.208", service: "tcp/443", want: query.VerdictPartial, paths: 2,
		},
		{
			name: "disabled rule is skipped",
			cfg: func() *firemon.Config {
				r := permit("1", "", "", "", "", "https")
				r.Disabled = true
				return lab(firemon.AddressStageOriginal, r)
			}(),
			src: "10.0.0.9", dst: "172.16.0.10", service: "tcp/443", want: query.VerdictDenied, paths: 1,
		},
		{
			name: "rule outside its schedule is skipped",
			cfg: func() *firemon.Config {
				r := permit("1", "", "", "", "", "https")
				r.Schedule = "nights"
				return lab(firemon.AddressStageOriginal, r)
			}(),
			src: "10.0.0.9", dst: "172.16.0.10", service: "tcp/443", want: query.VerdictDenied, paths: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, err := engine(t, tt.cfg).Query(query.Request{Src: addrs(t, tt.src), Dst: addrs(t, tt.dst), Service: svc(t, tt.service)})
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict != tt.want || len(res.Paths) != tt.paths {
				t.Fatalf("got %s with %d paths, want %s with %d", res.Verdict, len(res.Paths), tt.want, tt.paths)
			}
		})
	}
}

func TestEngine_ShadowedPieces(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal,
		deny("1", "", "", "10.0.0.5/32", ""),
		permit("2", "trust", "dmz", "10.0.0.0/8", "172.16.0.10/32", "https"))
	res, err := engine(t, cfg).Query(query.Request{Src: addrs(t, "10.0.0.0/24"), Dst: addrs(t, "172.16.0.10"), Service: svc(t, "tcp/443")})
	if err != nil {
		t.Fatal(err)
	}
	p := res.Paths[0]
	if p.From != "trust" || p.To != "dmz" || p.Ingress != "e1" || p.Egress != "e2" {
		t.Fatalf("path %+v", p)
	}
	if got := p.Region(query.OutcomeDeny).String(); got != "10.0.0.5 -> 172.16.0.10 tcp/443" {
		t.Errorf("denied: %s", got)
	}
	if got := p.Region(query.OutcomePermit); !got.ContainsSpace(traffic.Space{Src: addrs(t, "10.0.0.0-10.0.0.4,10.0.0.6-10.0.0.255"), Dst: addrs(t, "172.16.0.10"), Service: svc(t, "tcp/443")}) {
		t.Errorf("permitted: %s", got)
	}
}

func TestEngine_DestinationNAT(t *testing.T) {
	t.Parallel()
	dnat := firemon.DynamicNAT{
		ID:          "1",
		Destination: []firemon.AddressRef{inline("198.51.100.80/32")}, Services: []string{"http"},
		TranslatedDestination: firemon.Translation{Mode: firemon.TranslationModeAddress, Addresses: []firemon.AddressRef{inline("172.16.0.10/32")}, Port: 8080},
	}
	tests := []struct {
		name  string
		stage firemon.AddressStage
		rule  firemon.SecurityRule
	}{
		{"policy on translated address", firemon.AddressStageTranslated, permit("1", "untrust", "dmz", "", "172.16.0.10/32")},
		{"policy on original address with post-NAT zone", firemon.AddressStageOriginal, permit("1", "untrust", "dmz", "", "198.51.100.80/32", "http")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := lab(tt.stage, tt.rule)
			cfg.DynamicNATs = []firemon.DynamicNAT{dnat}
			res, err := engine(t, cfg).Query(query.Request{Src: addrs(t, "192.0.2.1"), Dst: addrs(t, "198.51.100.80"), Service: svc(t, "tcp/80")})
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict != query.VerdictAllowed || len(res.Paths) != 1 {
				t.Fatalf("got %s with %d paths", res.Verdict, len(res.Paths))
			}
			p := res.Paths[0]
			if p.DestinationNAT == nil || p.To != "dmz" || p.From != "untrust" {
				t.Fatalf("path %+v", p)
			}
		})
	}
}

func TestEngine_ZoneOverride(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal, permit("1", "l2-in", "l2-out", "", "", "https"))
	cfg.Zones = append(cfg.Zones, firemon.Zone{Name: "l2-in", Mode: firemon.ZoneModeLayer2}, firemon.Zone{Name: "l2-out", Mode: firemon.ZoneModeLayer2})
	res, err := engine(t, cfg).Query(query.Request{
		Src: addrs(t, "10.0.0.9"), Dst: addrs(t, "10.0.0.10"), Service: svc(t, "tcp/443"), FromZone: "l2-in", ToZone: "l2-out",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != query.VerdictAllowed {
		t.Fatalf("got %s", res.Verdict)
	}
}

func TestEngine_EmptyRequest(t *testing.T) {
	t.Parallel()
	if _, err := engine(t, lab(firemon.AddressStageOriginal)).Query(query.Request{}); err == nil {
		t.Fatal("want error")
	}
}

func TestEngine_Usage(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal,
		permit("1", "", "", "10.0.0.0/8", "172.16.0.10/32"),
		permit("2", "", "", "", "", "https"))
	cfg.Addresses = append(cfg.Addresses, firemon.Address{Name: "web", Entries: []firemon.AddressEntry{firemon.PrefixEntry(prefix("172.16.0.0/28"))}})
	u := engine(t, cfg).Usage(addrs(t, "172.16.0.10"), false)
	if len(u.Objects) != 1 || u.Objects[0].Name != "web" || u.Objects[0].Relation != traffic.RelationSuperset {
		t.Errorf("objects: %+v", u.Objects)
	}
	if len(u.Rules) != 1 || u.Rules[0].Rule.ID() != "1" || u.Rules[0].Destination != traffic.RelationEqual {
		t.Errorf("rules: %+v", u.Rules)
	}
}

func portOf(p uint16) traffic.PortRange { return traffic.Port(p) }
