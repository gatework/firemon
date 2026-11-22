package design_test

import (
	"testing"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
)

// A plan placed before a deny isolating a network carries a high risk;
// one opening a sensitive service across zones a medium one.
func TestPlan_Risks(t *testing.T) {
	t.Parallel()
	isolate := rule("9", firemon.ActionDeny, "trust", "dmz", []firemon.AddressRef{inline("10.0.0.0/16")}, nil)
	cfg := lab(isolate)
	in := intent(t, "10.0.1.5", "172.16.0.10", "tcp/3389")
	in.Override = true
	p := plan(t, cfg, in)
	fw, err := firemon.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Verified {
		t.Fatalf("plan %s %s", p.Status, p.VerifyError)
	}
	risks := p.Risks(fw)
	codes := map[design.RiskCode]design.RiskLevel{}
	for _, r := range risks {
		codes[r.Code] = r.Level
	}
	if codes[design.RiskBypassIsolation] != design.RiskHigh || codes[design.RiskSensitiveService] != design.RiskMedium {
		t.Fatalf("risks %+v", risks)
	}
	if risks[0].Level != design.RiskHigh {
		t.Fatalf("most severe first: %+v", risks)
	}
}
