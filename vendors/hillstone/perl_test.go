package hillstone_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/query"
	"github.com/gatework/firemon/traffic"
	"github.com/gatework/firemon/vendors/hillstone"
)

// TestPerlSearchEquivalence checks that v2 design reaches the same decision
// as the Perl Searcher for each recorded case (GEN-2): "ignore" means the
// intent is already permitted, "modify" extends the named rule, "new" adds a
// rule.
func TestPerlSearchEquivalence(t *testing.T) {
	t.Parallel()
	dir := filepath.Join("testdata", "perl")
	raw, err := os.ReadFile(filepath.Join(dir, "hillstone.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := hillstone.New(hillstone.Options{}).Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var want struct {
		Cases []struct {
			Name string  `json:"name"`
			Rule *string `json:"rule"`
			Type string  `json:"type"`
		} `json:"cases"`
	}
	golden, err := os.ReadFile(filepath.Join(dir, "hillstone-search.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(golden, &want); err != nil {
		t.Fatal(err)
	}
	// The cases of search.pl, in order.
	inputs := map[string][3]string{
		"covered":         {"192.0.2.10/32", "192.0.2.10/32", "tcp/80,tcp/443"},
		"append-source":   {"192.0.2.11/32", "192.0.2.10/32", "tcp/80,tcp/443"},
		"create-two-axes": {"192.0.2.11/32", "192.0.2.12/32", "tcp/80,tcp/443"},
		"append-service":  {"192.0.2.10/32", "192.0.2.10/32", "tcp/8080"},
	}
	planner := design.New(fw, design.Options{Now: func() time.Time { return time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC) }})
	for _, c := range want.Cases {
		in, ok := inputs[c.Name]
		if !ok {
			t.Fatalf("no input for Perl case %q", c.Name)
		}
		intent := design.Intent{FromZone: "inside", ToZone: "inside"}
		intent.Src, _ = traffic.ParseAddressSet(in[0])
		intent.Dst, _ = traffic.ParseAddressSet(in[1])
		intent.Service, _ = traffic.ParseServiceSet(in[2])
		p, err := planner.Plan(intent)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		got, rule := decision(t, fw, intent, p)
		wantRule := ""
		if c.Rule != nil {
			wantRule = *c.Rule
		}
		if got != c.Type || rule != wantRule || !p.Verified {
			t.Errorf("%s: v2 %s rule %q verified=%v, Perl %s rule %q", c.Name, got, rule, p.Verified, c.Type, wantRule)
		}
	}
}

// decision maps a v2 plan to the Perl result vocabulary. For an intent
// that is already permitted, the rule is the one the query says decides it.
func decision(t *testing.T, fw *firemon.Firewall, in design.Intent, p *design.Plan) (kind, rule string) {
	t.Helper()
	if p.Status == design.StatusNoChange {
		res, err := query.New(fw, query.Options{}).Query(query.Request{Src: in.Src, Dst: in.Dst, Service: in.Service, FromZone: in.FromZone, ToZone: in.ToZone})
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range res.Paths[0].Decisions {
			if d.Outcome == query.OutcomePermit && d.Rule != nil {
				return "ignore", d.Rule.ID()
			}
		}
		return "ignore", ""
	}
	for _, ch := range p.Changes {
		switch c := ch.(type) {
		case design.ExtendRule:
			return "modify", c.RuleID
		case design.AddRule:
			return "new", ""
		}
	}
	return p.Status.String(), ""
}
