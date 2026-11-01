package policy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestNATEffectProofIncludesScopesWithoutPolicy(t *testing.T) {
	base, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	q := policy.Request{Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")}
	data := base.Export()
	data.StaticNATs = []fm.StaticNATRecord{{Object: fm.Object{ID: "intended"}, Match: anyMatch(), Source: []fm.Mapping{{Original: rangeOf("192.0.2.1/32"), Translated: rangeOf("203.0.113.1/32"), Mode: fm.Offset}}}}
	// Narrow intent cannot exempt a broad declaration, including other services.
	after, _ := fm.Seal(data)
	intent := []policy.NATIntent{{Request: q, Steps: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "intended"}}}}
	if _, err := (policy.Engine{}).ProveNATEffects(context.Background(), base, after, intent); err == nil {
		t.Fatal("outside ports or destinations changed")
	}
	// An intent for the complete effective domain is valid, but a hidden scope is not.
	all, _ := flow.AllTraffic(4096)
	regions := all.Regions()
	var selected []flow.TrafficRegion
	for _, r := range regions {
		if r.Source.First.Is4() && r.Destination.First.Is4() {
			r.Source = rangeOf("192.0.2.1/32")
			selected = append(selected, r)
		}
	}
	intent[0].Request.Traffic, _ = flow.NewTraffic(4096, selected...)
	if _, err := (policy.Engine{}).ProveNATEffects(context.Background(), base, after, intent); err != nil {
		t.Fatal(err)
	}
	hidden := data.StaticNATs[0]
	hidden.ID = "hidden"
	hidden.Scope = "nat-only"
	data.StaticNATs = append(data.StaticNATs, hidden)
	after, _ = fm.Seal(data)
	if _, err := (policy.Engine{}).ProveNATEffects(context.Background(), base, after, intent); err == nil {
		t.Fatal("scope absent from policy escaped proof")
	}
}

func TestNATEffectProofPreflightsStepsRegionsAndContexts(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	q := policy.Request{Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")}
	for _, kind := range []string{"steps", "regions", "contexts"} {
		t.Run(kind, func(t *testing.T) {
			intent := policy.NATIntent{Request: q, Steps: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "missing"}}}
			limits := policy.Limits{MaxVisits: 64}
			switch kind {
			case "steps":
				intent.Steps = make([]policy.NATStep, 65)
			case "regions":
				box := q.Traffic.Regions()[0]
				var regions []flow.TrafficRegion
				for i := range 65 {
					box.SourcePort = flow.Interval{Low: uint16(i * 2), High: uint16(i * 2)}
					regions = append(regions, box)
				}
				intent.Request.Traffic, err = flow.NewTraffic(100, regions...)
				if err != nil {
					t.Fatal(err)
				}
			case "contexts":
				limits.MaxCombinations = 1
			}
			_, err := (policy.Engine{Limits: limits}).ProveNATEffects(context.Background(), fw, fw, []policy.NATIntent{intent})
			if !errors.Is(err, policy.ErrBudget) {
				t.Fatalf("proof traversed invalid step before capacity rejection: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = (policy.Engine{Limits: limits}).ProveNATEffects(ctx, fw, fw, []policy.NATIntent{intent})
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}

type nativeCancelCheckpoint struct {
	context.Context
	checks, limit int
}

func (c *nativeCancelCheckpoint) Err() error {
	c.checks++
	if c.checks >= c.limit {
		return context.Canceled
	}
	return nil
}
func TestNATEffectProofCancelsDuringIntentPreflight(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	q := policy.Request{Traffic: traffic(t, "192.0.2.1/32", "198.51.100.1/32")}
	intents := make([]policy.NATIntent, 8)
	for i := range intents {
		intents[i] = policy.NATIntent{Request: q, Steps: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "missing"}}}
	}
	ctx := &nativeCancelCheckpoint{Context: context.Background(), limit: 8}
	_, err = (policy.Engine{Limits: policy.Limits{MaxVisits: 100}}).ProveNATEffects(ctx, fw, fw, intents)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestNATProofConcreteEgressDomain(t *testing.T) {
	d := stonePacketData()
	d.StaticNATs = nil
	d.Addresses = []fm.AddressRecord{{Object: fm.Object{ID: "src"}, Ranges: []flow.AddressRange{rangeOf("198.51.100.20/32")}}}
	base, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	m := anyMatch()
	m.AnySource = false
	m.Sources = []fm.AddressRef{{Kind: fm.AddressObject, ID: "src"}}
	n := fm.DynamicNATRecord{Object: fm.Object{ID: "pat", Scope: "vr"}, Match: m, Order: fm.NATOrder{Stage: 2, Section: "snat"}, SourceMode: fm.InterfaceIP, DestinationMode: fm.NoTranslation, Interface: "left"}
	d.DynamicNATs = []fm.DynamicNATRecord{n}
	after, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := flow.AllTraffic(4096)
	var boxes []flow.TrafficRegion
	for _, b := range all.Regions() {
		if b.Source.First.Is4() && b.Destination.First.Is4() {
			b.Source = rangeOf("198.51.100.20/32")
			boxes = append(boxes, b)
		}
	}
	domain, _ := flow.NewTraffic(4096, boxes...)
	intent := policy.NATIntent{Request: policy.Request{Scope: "vr", EgressInterface: "left", Traffic: domain}, Steps: []policy.NATStep{{Kind: fm.DynamicNATObject, ID: "pat"}}}
	proof, err := (policy.Engine{}).ProveNATEffects(t.Context(), base, after, []policy.NATIntent{intent})
	if err != nil || !proof.OutsidePreserved {
		t.Fatal("concrete exhaustive domain refused", proof, err)
	}
	q := intent.Request
	q.EgressInterface = ""
	got, err := (policy.Engine{}).QueryNAT(t.Context(), after, q)
	if err != nil || got.Complete || got.Unknown.Empty() {
		t.Fatal("direct missing egress became certain", got, err)
	}
	intent.Request.EgressInterface = ""
	if _, err := (policy.Engine{}).ProveNATEffects(t.Context(), base, after, []policy.NATIntent{intent}); err == nil {
		t.Fatal("underspecified intent accepted")
	}
	intent.Request.EgressInterface = "left"
	other := n
	other.ID = "other"
	other.Interface = "right"
	d.DynamicNATs = append(d.DynamicNATs, other)
	outside, _ := fm.Seal(d)
	if _, err := (policy.Engine{}).ProveNATEffects(t.Context(), base, outside, []policy.NATIntent{intent}); err == nil {
		t.Fatal("unrequested other egress changed")
	}
	for _, kind := range []string{"disabled", "missing", "invalid"} {
		t.Run(kind, func(t *testing.T) {
			bad := after.Export()
			switch kind {
			case "disabled":
				bad.Interfaces[1].Disabled = true
			case "missing":
				bad.Interfaces = nil
			case "invalid":
				bad.Interfaces[1].Unsupported = []string{"unknown"}
			}
			fw, err := fm.Seal(bad)
			if err != nil {
				return
			}
			if _, err := (policy.Engine{}).ProveNATEffects(t.Context(), base, fw, []policy.NATIntent{intent}); err == nil {
				t.Fatal("unestablished egress accepted")
			}
		})
	}
}

func TestFiniteNATIntentCannotExemptPermanentTranslation(t *testing.T) {
	base, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}})
	if err != nil {
		t.Fatal(err)
	}
	data := base.Export()
	data.StaticNATs = []fm.StaticNATRecord{{Object: fm.Object{ID: "fixed"}, Match: anyMatch(), Source: []fm.Mapping{{Original: rangeOf("192.0.2.1/32"), Translated: rangeOf("203.0.113.1/32"), Mode: fm.Offset}}}}
	after, err := fm.Seal(data)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := flow.AllTraffic(4096)
	r := all.Regions()[0]
	r.Source = rangeOf("192.0.2.1/32")
	domain, _ := flow.NewTraffic(4096, r)
	at := time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)
	intent := policy.NATIntent{Request: policy.Request{Traffic: domain, At: at}, Steps: []policy.NATStep{{Kind: fm.StaticNATObject, ID: "fixed"}}}
	if _, err := (policy.Engine{}).ProveNATEffects(t.Context(), base, after, []policy.NATIntent{intent}); err != nil {
		t.Fatal(err)
	}
	intent.Window = &fm.TimeWindow{Start: at, End: at.Add(time.Hour)}
	if _, err := (policy.Engine{}).ProveNATEffects(t.Context(), base, after, []policy.NATIntent{intent}); err == nil {
		t.Fatal("permanent mapping escaped outside-time proof")
	}
}
