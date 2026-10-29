package policy_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestEvaluationInputAndCancellationContract(t *testing.T) {
	e := policy.Engine{}
	for name, call := range map[string]func(context.Context) error{
		"query":            func(ctx context.Context) error { _, err := e.Query(ctx, nil, policy.Request{}); return err },
		"nat":              func(ctx context.Context) error { _, err := e.QueryNAT(ctx, nil, policy.Request{}); return err },
		"packet":           func(ctx context.Context) error { _, err := e.QueryPacket(ctx, nil, policy.PacketRequest{}); return err },
		"routes":           func(ctx context.Context) error { _, err := e.ResolveRoutes(ctx, nil, "", flow.Set{}); return err },
		"contexts":         func(ctx context.Context) error { _, err := e.Contexts(ctx, time.Time{}, nil); return err },
		"equivalence":      func(ctx context.Context) error { _, err := e.Equivalent(ctx, nil, nil, time.Time{}); return err },
		"nat preservation": func(ctx context.Context) error { return e.PreserveNAT(ctx, nil, nil, time.Time{}) },
		"append": func(ctx context.Context) error {
			_, err := e.AppendCanPreserve(ctx, nil, nil, "", policy.Request{}, policy.Result{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := call(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
			if err := call(context.Background()); !errors.Is(err, policy.ErrInvalid) {
				t.Fatalf("invalid input misclassified: %v", err)
			}
		})
	}
}

func TestRoutesHonorEngineBudgetAndEmptyCancellation(t *testing.T) {
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "test", Vendor: "huawei"}, Routes: []fm.RouteRecord{
		{Object: fm.Object{ID: "one", Scope: "vr"}, Destination: netip.MustParsePrefix("192.0.2.0/24")},
		{Object: fm.Object{ID: "two", Scope: "vr"}, Destination: netip.MustParsePrefix("198.51.100.0/24")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	addresses, _ := flow.NewSet(rangeOf("192.0.2.0/24"))
	if _, err := (policy.Engine{Limits: policy.Limits{MaxVisits: 1}}).ResolveRoutes(context.Background(), fw, "vr", addresses); !errors.Is(err, policy.ErrBudget) {
		t.Fatalf("route budget ignored: %v", err)
	}
	if _, err := (policy.Engine{Limits: policy.Limits{MaxVisits: 1}}).ResolveRoutes(context.Background(), fw, "other", addresses); err != nil {
		t.Fatal("foreign VRF charged", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (policy.Engine{}).ResolveRoutes(ctx, fw, "other", flow.Set{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("empty resolution skipped cancellation: %v", err)
	}
}
