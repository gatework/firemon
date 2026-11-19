package design_test

import (
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/traffic"
)

// Among rules that can carry the request without opening anything else,
// the one that already connects the same ends is modified, then one that
// logs; new rules log their sessions and say why they exist.
func TestPlanner_ElectsTheBestRuleToModify(t *testing.T) {
	t.Parallel()
	addr := func(s string) []firemon.AddressRef { return []firemon.AddressRef{inline(s)} }
	withSSH := func(rules ...firemon.SecurityRule) *firemon.Config {
		c := lab(rules...)
		c.Services = append(c.Services, firemon.Service{Name: "SSH22", Entries: []firemon.ServiceEntry{firemon.PortEntry(traffic.ProtocolTCP, traffic.Port(22))}})
		return c
	}
	pick := func(c *firemon.Config) string {
		p := plan(t, c, intent(t, "10.0.1.5", "172.16.0.10", "tcp/443"))
		for _, ch := range p.Changes {
			if x, ok := ch.(design.ExtendRule); ok {
				return x.RuleID + " " + x.Field.String()
			}
		}
		return "none: " + p.Status.String()
	}
	otherSource := rule("1", firemon.ActionPermit, "trust", "dmz", addr("10.0.1.6/32"), addr("172.16.0.10/32"), "HTTPS")
	sameEnds := rule("2", firemon.ActionPermit, "trust", "dmz", addr("10.0.1.5/32"), addr("172.16.0.10/32"), "SSH22")
	if got := pick(withSSH(otherSource, sameEnds)); got != "2 service" {
		t.Errorf("the rule connecting the same ends is modified: %s", got)
	}
	quiet := sameEnds
	quiet.ID = "3"
	logging := sameEnds
	logging.ID = "4"
	logging.Log = firemon.Logging{End: true}
	if got := pick(withSSH(quiet, logging)); got != "4 service" {
		t.Errorf("a rule that logs is preferred: %s", got)
	}
	// A new rule logs and explains itself.
	p := plan(t, lab(), intent(t, "10.0.1.5", "172.16.0.10", "tcp/443"))
	add, ok := p.Changes[len(p.Changes)-1].(design.AddRule)
	if !ok || !add.Rule.Log.Start || !add.Rule.Log.End || add.Rule.Description == "" {
		t.Fatalf("new rule %+v", p.Changes)
	}
	in := intent(t, "10.0.1.5", "172.16.0.10", "tcp/443")
	in.NoLog = true
	p = plan(t, lab(), in)
	if add := p.Changes[len(p.Changes)-1].(design.AddRule); add.Rule.Log.Enabled() {
		t.Fatalf("--no-log: %+v", add.Rule.Log)
	}
}
