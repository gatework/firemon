package policy_test

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestResolutionSeparatesUnknownFromExecutionFailure(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "test", Vendor: "huawei"},
		AddressGroups: []fm.AddressGroupRecord{{Object: fm.Object{ID: "g"}, Members: []fm.AddressRef{{Kind: fm.AddressGroupObject, ID: "g"}}}},
		ServiceGroups: []fm.ServiceGroupRecord{{Object: fm.Object{ID: "g"}, Members: []fm.ServiceRef{{Kind: fm.ServiceGroupObject, ID: "g"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	addresses := []fm.AddressRef{{Kind: fm.AddressGroupObject, ID: "g"}}
	services := []fm.ServiceRef{{Kind: fm.ServiceGroupObject, ID: "g"}}
	e := policy.Engine{}
	if _, known, err := e.ResolveAddresses(context.Background(), fw, addresses, false); err != nil || known {
		t.Fatalf("cycle: %v %v", known, err)
	}
	if _, known, err := e.ResolveServices(context.Background(), fw, services, false); err != nil || known {
		t.Fatalf("cycle: %v %v", known, err)
	}
	e.Limits.MaxCombinations = 1
	if _, _, err := e.ResolveAddresses(context.Background(), fw, addresses, false); !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("budget: %v", err)
	}
	if _, _, err := e.ResolveServices(context.Background(), fw, services, false); !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("budget: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := e.ResolveAddresses(ctx, fw, nil, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel any: %v", err)
	}
	if _, _, err := e.ResolveServices(ctx, fw, nil, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel any: %v", err)
	}
	if _, _, err := e.ResolveAddresses(context.Background(), nil, nil, true); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("nil graph: %v", err)
	}
	if _, _, err := e.ResolveServices(context.Background(), nil, nil, true); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("nil graph: %v", err)
	}
	if _, _, err := e.Match(context.Background(), nil, fm.Match{ZoneRelation: fm.SameZone}, policy.Request{}, flow.Traffic{}); !errors.Is(err, policy.ErrInvalid) {
		t.Fatalf("nil match graph: %v", err)
	}
}
