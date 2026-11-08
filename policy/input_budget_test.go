package policy_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestQueryInputBudgetPrecedesShortcuts(t *testing.T) {
	input, err := traffic(t, "192.0.2.1/32", "198.51.100.1/32").Union(traffic(t, "192.0.2.3/32", "198.51.100.1/32"), 2)
	if err != nil || input.RegionCount() != 2 {
		t.Fatal("fixture", input.RegionCount(), err)
	}
	addresses, err := flow.NewAddressSet(rangeOf("192.0.2.1/32"), rangeOf("192.0.2.3/32"))
	if err != nil {
		t.Fatal(err)
	}
	mismatch := anyMatch()
	mismatch.AnyFromZone, mismatch.FromZones = false, []fm.ID{"other"}
	for _, fixture := range []struct {
		name        string
		rules       []fm.RuleRecord
		diagnostics []fm.Diagnostic
	}{
		{name: "empty"},
		{name: "unknown", diagnostics: []fm.Diagnostic{{Code: "unparsed", Message: "unknown policy"}}},
		{name: "disabled", rules: []fm.RuleRecord{{Object: fm.Object{ID: "rule"}, Disabled: true, Match: anyMatch(), Action: fm.Permit, RuleSet: "security"}}},
		{name: "other scope", rules: []fm.RuleRecord{{Object: fm.Object{ID: "rule", Scope: "other"}, Match: anyMatch(), Action: fm.Permit, RuleSet: "security"}}},
		{name: "other zone", rules: []fm.RuleRecord{{Object: fm.Object{ID: "rule"}, Match: mismatch, Action: fm.Permit, RuleSet: "security"}}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "paloalto"}, Rules: fixture.rules, Diagnostics: fixture.diagnostics})
			if err != nil {
				t.Fatal(err)
			}
			q := policy.Request{Traffic: input, FromZone: "in", ToZone: "out"}
			for _, entry := range []struct {
				name string
				run  func(context.Context, policy.Engine, *fm.Firewall) (any, error)
			}{
				{"policy", func(ctx context.Context, e policy.Engine, fw *fm.Firewall) (any, error) { return e.Query(ctx, fw, q) }},
				{"nat", func(ctx context.Context, e policy.Engine, fw *fm.Firewall) (any, error) {
					return e.QueryNAT(ctx, fw, q)
				}},
				{"packet", func(ctx context.Context, e policy.Engine, fw *fm.Firewall) (any, error) {
					return e.QueryPacket(ctx, fw, policy.PacketRequest{Request: q})
				}},
				{"aliases", func(ctx context.Context, e policy.Engine, fw *fm.Firewall) (any, error) {
					return e.DiscoverStaticAliases(ctx, fw, policy.PacketRequest{Request: q}, policy.RealView)
				}},
				{"routes", func(ctx context.Context, e policy.Engine, fw *fm.Firewall) (any, error) {
					return e.ResolveRoutes(ctx, fw, "", addresses)
				}},
				{"match", func(ctx context.Context, e policy.Engine, fw *fm.Firewall) (any, error) {
					// Match must bound its actual input, independently of q.Traffic.
					matched, known, err := e.Match(ctx, fw, mismatch, policy.Request{FromZone: "in"}, input)
					return struct {
						Traffic flow.Traffic
						Known   bool
					}{matched, known}, err
				}},
			} {
				t.Run(entry.name, func(t *testing.T) {
					e := policy.Engine{Limits: policy.Limits{MaxRegions: 1}}
					got, err := entry.run(t.Context(), e, fw)
					if !errors.Is(err, policy.ErrBudget) || !reflect.ValueOf(got).IsZero() {
						t.Fatalf("over-budget %T result: empty=%t, err=%v", got, reflect.ValueOf(got).IsZero(), err)
					}
					e.Limits.MaxRegions = 2
					if _, err := entry.run(t.Context(), e, fw); err != nil {
						t.Fatalf("exact limit rejected: %v", err)
					}
					e.Limits.MaxRegions = 1
					if _, err := entry.run(t.Context(), e, nil); !errors.Is(err, policy.ErrInvalid) {
						t.Fatalf("invalid graph lost precedence: %v", err)
					}
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					if _, err := entry.run(ctx, e, nil); !errors.Is(err, context.Canceled) {
						t.Fatalf("cancellation lost precedence: %v", err)
					}
				})
			}
		})
	}
}

func TestMatchBudgetsActualInput(t *testing.T) {
	input := traffic(t, "192.0.2.1/32", "198.51.100.1/32")
	request, err := input.Union(traffic(t, "192.0.2.3/32", "198.51.100.1/32"), 2)
	if err != nil {
		t.Fatal(err)
	}
	e := policy.Engine{Limits: policy.Limits{MaxRegions: 1}}
	matched, known, err := e.Match(t.Context(), base(t, nil), anyMatch(), policy.Request{Traffic: request}, input)
	if err != nil || !known || !reflect.DeepEqual(matched.Regions(), input.Regions()) {
		t.Fatalf("bounded matching input rejected: %v, %v, %v", matched, known, err)
	}
}
