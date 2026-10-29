package plan_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/policy"
	"github.com/gatework/firemon/vendors/hillstone"
)

func TestIndependentReadbackAcceptsNativeAllocatedIDsAndRenumberedPositions(t *testing.T) {
	p, err := (plan.Planner{Renderer: renderer{rejectAppend: true}}).Plan(context.Background(), baseline(t), []policy.Request{request(t, "192.0.2.2/32")})
	if err != nil {
		t.Fatal(err)
	}
	d := p.After().Export()
	planned := p.Changes()[0].Rule
	for i := range d.Rules {
		d.Rules[i].Position += 400
		d.Rules[i].Spans = []fm.Span{{First: 500 + i, Last: 510 + i}}
		if d.Rules[i].ID == planned {
			d.Rules[i].ID, d.Rules[i].Name = "217", "217"
		}
	}
	observed, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := p.Verify(context.Background(), observed)
	if err != nil {
		t.Fatal(err)
	}
	if proof.ObservedDigest != observed.SemanticDigest() || proof.PlanDigest != p.Digest() || proof.RuleIDs()[planned] != "217" {
		t.Fatal("readback not bound to actual graph and native ID")
	}
	ids := proof.RuleIDs()
	ids[planned] = "mutable"
	if proof.RuleIDs()[planned] != "217" {
		t.Fatal("proof aliases caller map")
	}
}

func TestReadbackComparesIndependentNativeConfigurationWithStableRouteIdentity(t *testing.T) {
	raw := "zone outside\nexit\ninterface wan\nzone outside\nip address 198.51.100.2/24\nexit\nip route 0.0.0.0/0 198.51.100.254\naddress src\nip 192.0.2.1/32\nexit\naddress dst\nip 198.51.100.1/32\nexit\nservice https\ntcp dst-port 443 443\nexit\nrule id 10\nsrc-zone any\ndst-zone any\nsrc-addr src\ndst-addr dst\nservice https\naction permit\nexit\n"
	metadata := fm.Metadata{Device: "fw"}
	fw, err := hillstone.Parse(context.Background(), config.Source{Text: raw, Complete: true}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Complete() {
		t.Fatal(fw.Diagnostics())
	}
	p, err := (plan.Planner{Renderer: hillstone.Renderer{}}).Plan(context.Background(), fw, []policy.Request{request(t, "192.0.2.2/32")})
	if err != nil {
		t.Fatal(err)
	}
	ref := p.Changes()[0].Sources[0].ID
	readback := fmt.Sprintf("address %s\nip 192.0.2.2/32\nexit\n", ref) + raw + fmt.Sprintf("rule id 10\nsrc-addr %s\nexit\n", ref)
	observed, err := hillstone.Parse(context.Background(), config.Source{Text: readback, Complete: true}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Verify(context.Background(), observed); err != nil {
		t.Fatal("independent readback failed", err)
	}
	unchanged, err := hillstone.Parse(context.Background(), config.Source{Text: "\n\n" + raw, Complete: true}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyBaseline(context.Background(), unchanged); err != nil {
		t.Fatal("line offsets changed baseline identity", err)
	}
}

func TestPlanDigestRejectsUnencodableRequestTime(t *testing.T) {
	q := request(t, "192.0.2.1/32")
	q.At = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := (plan.Planner{}).Plan(context.Background(), baseline(t), []policy.Request{q}); err == nil {
		t.Fatal("failed serialization received a plan digest")
	}
}

func TestReadbackRejectsUnrelatedChangesEvenWhenRequestedTrafficIsAllowed(t *testing.T) {
	p, err := (plan.Planner{Renderer: renderer{}}).Plan(context.Background(), baseline(t), []policy.Request{request(t, "192.0.2.2/32")})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*fm.Data)
	}{
		{"logging", func(d *fm.Data) { d.Rules[0].Log = fm.Known }},
		{"extra address", func(d *fm.Data) {
			d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: "unapproved"}, Ranges: []flow.AddressRange{addressRange("203.0.113.1/32")}})
		}},
		{"NAT", func(d *fm.Data) {
			d.StaticNATs = append(d.StaticNATs, fm.StaticNATRecord{Object: fm.Object{ID: "unapproved"}, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}, Source: []fm.Mapping{{Original: addressRange("192.0.2.0/24"), Translated: addressRange("203.0.113.0/24"), Mode: fm.Offset}}})
		}},
		{"incomplete", func(d *fm.Data) { d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Code: "incomplete-source"}) }},
		{"device", func(d *fm.Data) { d.Metadata.Device = "another-device" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := p.After().Export()
			test.change(&d)
			fw, err := fm.Seal(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Verify(context.Background(), fw); !errors.Is(err, plan.ErrReadback) {
				t.Fatalf("unapproved %s accepted: %v", test.name, err)
			}
		})
	}
}

func TestReadbackRejectsRuleReorderingAndBaselineIDReuse(t *testing.T) {
	p, err := (plan.Planner{Renderer: renderer{rejectAppend: true}}).Plan(context.Background(), baseline(t), []policy.Request{request(t, "192.0.2.2/32")})
	if err != nil {
		t.Fatal(err)
	}
	for _, swapID := range []bool{false, true} {
		d := p.After().Export()
		if swapID {
			d.Rules[0].ID, d.Rules[1].ID = d.Rules[1].ID, d.Rules[0].ID
		} else {
			d.Rules[0].Position, d.Rules[1].Position = d.Rules[1].Position, d.Rules[0].Position
		}
		fw, err := fm.Seal(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Verify(context.Background(), fw); !errors.Is(err, plan.ErrReadback) {
			t.Fatalf("native order/identity changed: %v", err)
		}
	}
}
