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

// A rule that matches any service but only some applications is judged by
// the applications' standard ports when the request names no application:
// off those ports it does not match; on them it may; a rule with its own
// service is not narrowed, since it names the port the application uses.
func TestApplicationRule_StandardPorts(t *testing.T) {
	t.Parallel()
	req := func(s string) query.Request {
		return query.Request{Src: addrs(t, "10.0.0.9"), Dst: addrs(t, "172.16.0.10"), Service: svc(t, s)}
	}
	tests := []struct {
		name    string
		rules   []string
		service string
		want    query.Verdict
		noted   bool
	}{
		{"off the application's ports the rule does not match", []string{"no-ssh", "rest"}, "tcp/12345", query.VerdictAllowed, true},
		{"on its port it may match", []string{"no-ssh", "rest"}, "tcp/22", query.VerdictIndeterminate, false},
		{"a rule with its own service is not narrowed", []string{"web-8080", "rest"}, "tcp/8080", query.VerdictIndeterminate, false},
		{"an application without known ports may match any port", []string{"unknown-app", "rest"}, "tcp/12345", query.VerdictAllowed, false},
		{"an unknown application may still change the outcome", []string{"unknown-app", "no-ssh"}, "tcp/12345", query.VerdictIndeterminate, true},
	}
	all := lab(firemon.AddressStageOriginal,
		firemon.SecurityRule{ID: "no-ssh", Action: firemon.ActionDeny, Applications: []string{"SSH"}},
		firemon.SecurityRule{ID: "web-8080", Action: firemon.ActionDeny, Applications: []string{"HTTP"}, Services: []string{"tcp-8080"}},
		firemon.SecurityRule{ID: "unknown-app", Action: firemon.ActionPermit, Applications: []string{"Acme"}},
		permit("rest", "", "", "", ""))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := *all
			c.Rules = nil
			for _, id := range tt.rules {
				for _, r := range all.Rules {
					if r.ID == id {
						c.Rules = append(c.Rules, r)
					}
				}
			}
			c.Services = append(c.Services, firemon.Service{Name: "tcp-8080", Entries: []firemon.ServiceEntry{firemon.PortEntry(6, portOf(8080))}})
			c.Applications = firemon.ServiceBook{"ssh": {firemon.PortEntry(6, portOf(22))}, "http": {firemon.PortEntry(6, portOf(80))}}
			res := queryOne(t, &c, req(tt.service))
			if res.Verdict != tt.want {
				t.Fatalf("got %s, want %s", res.Verdict, tt.want)
			}
			if noted := len(res.Paths[0].AppPorts) > 0; noted != tt.noted {
				t.Fatalf("assumption recorded %v, want %v", noted, tt.noted)
			}
		})
	}
}
