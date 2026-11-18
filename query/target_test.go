package query_test

import (
	"net/netip"
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
)

func domainLab() *firemon.Config {
	cfg := lab(firemon.AddressStageOriginal,
		firemon.SecurityRule{ID: "web", Action: firemon.ActionPermit, Services: []string{"https"},
			Destination: []firemon.AddressRef{firemon.InlineAddress(firemon.FQDNEntry("*.example.com"))}},
		deny("block", "", "", "", "198.51.100.7/32"),
		permit("rest", "", "", "", ""))
	return cfg
}

func TestDomainTarget_MatchesByName(t *testing.T) {
	t.Parallel()
	res := queryOne(t, domainLab(), query.Request{Src: addrs(t, "10.0.0.9"), DstDomains: []string{"a.example.com"}, Service: svc(t, "tcp/443")})
	if res.Verdict != query.VerdictAllowed || res.Paths[0].Domain != "a.example.com" || res.Paths[0].To != "untrust" {
		t.Fatalf("got %s %+v", res.Verdict, res.Paths)
	}
}

func TestDomainTarget_AddressRulesNeedResolution(t *testing.T) {
	t.Parallel()
	cfg := domainLab()
	unresolved := query.Request{Src: addrs(t, "10.0.0.9"), DstDomains: []string{"other.test"}, Service: svc(t, "tcp/443")}
	if res := queryOne(t, cfg, unresolved); res.Verdict != query.VerdictIndeterminate {
		t.Fatalf("an address-only deny may match an unresolved name: %s", res.Verdict)
	}
	resolved := unresolved
	resolved.Resolved = map[string][]netip.Addr{"other.test": {netip.MustParseAddr("198.51.100.7")}}
	if res := queryOne(t, cfg, resolved); res.Verdict != query.VerdictDenied || !res.Paths[0].DomainResolved {
		t.Fatalf("a resolved name is matched by address: %s", res.Verdict)
	}
}

func TestApplicationTarget(t *testing.T) {
	t.Parallel()
	cfg := lab(firemon.AddressStageOriginal,
		firemon.SecurityRule{ID: "ssh", Action: firemon.ActionPermit, Applications: []string{"SSH"}, ApplicationDefault: true})
	cfg.Applications = firemon.ServiceBook{"ssh": {firemon.PortEntry(6, portOf(22))}}
	tests := []struct {
		name string
		req  query.Request
		want query.Verdict
	}{
		{"named application on its default port", query.Request{Src: addrs(t, "10.0.0.9"), Dst: addrs(t, "172.16.0.10"), Service: svc(t, "any"), Applications: []string{"ssh"}}, query.VerdictAllowed},
		{"other application is not matched", query.Request{Src: addrs(t, "10.0.0.9"), Dst: addrs(t, "172.16.0.10"), Service: svc(t, "any"), Applications: []string{"ms-rdp"}}, query.VerdictDenied},
		{"no application named stays undecided", query.Request{Src: addrs(t, "10.0.0.9"), Dst: addrs(t, "172.16.0.10"), Service: svc(t, "tcp/22")}, query.VerdictIndeterminate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := queryOne(t, cfg, tt.req).Verdict; got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}
