package plan

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/policy"
)

func TestNameReservationsIncludePendingCreations(t *testing.T) {
	visits := visitBudget(100)
	names, err := newNameAllocator(context.Background(), &fm.Data{Metadata: fm.Metadata{Vendor: "huawei"}}, &visits)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []fm.ID{"generated", "generated-new", "generated-new-new"} {
		service, err := names.object(context.Background(), "generated", names.services)
		if err != nil || service != want {
			t.Fatalf("pending service: %s, %v; want %s", service, err, want)
		}
		rule, err := names.rule(context.Background(), "generated", fm.RuleRecord{RuleSet: "security"})
		if err != nil || rule != want {
			t.Fatalf("pending rule: %s, %v; want %s", rule, err, want)
		}
	}
}

func TestNameReservationChargesBeforeMutation(t *testing.T) {
	visits := visitBudget(1) // One probe fits; the reservation does not.
	names, err := newNameAllocator(context.Background(), &fm.Data{}, &visits)
	if err != nil {
		t.Fatal(err)
	}
	id, err := names.object(context.Background(), "new", names.services)
	if id != "" || !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("unbudgeted reservation: %s, %v", id, err)
	}
	visits = 2
	id, err = names.object(context.Background(), "new", names.services)
	if err != nil || id != "new" {
		t.Fatalf("failed reservation consumed name: %s, %v", id, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := names.rule(ctx, "new", fm.RuleRecord{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
