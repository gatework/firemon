package policy_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestPreservationBudgetsCatalogBeforeCopying(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}}
	for i := range 1000 {
		d.Addresses = append(d.Addresses, fm.AddressRecord{Object: fm.Object{ID: fm.ID(fmt.Sprint(i))}, Ranges: []flow.AddressRange{rangeOf("192.0.2.1/32")}})
	}
	d.StaticNATs = []fm.StaticNATRecord{{Object: fm.Object{ID: "fixed"}, Match: anyMatch(), Source: []fm.Mapping{{Original: rangeOf("192.0.2.0/24"), Translated: rangeOf("203.0.113.0/24"), Mode: fm.Offset}}}}
	fw, err := fm.Seal(d)
	if err != nil || !fw.Complete() {
		t.Fatalf("fixture: %v", err)
	}
	for _, natOnly := range []bool{false, true} {
		for _, limit := range []int{32, 100000} {
			engine := policy.Engine{Limits: policy.Limits{MaxVisits: limit}}
			check := func(ctx context.Context) error {
				if natOnly {
					return engine.PreserveNAT(ctx, fw, fw, time.Time{})
				}
				_, err := engine.Equivalent(ctx, fw, fw, time.Time{})
				return err
			}
			var start, end runtime.MemStats
			runtime.ReadMemStats(&start)
			err := check(context.Background())
			runtime.ReadMemStats(&end)
			if limit == 32 {
				if !errors.Is(err, policy.ErrBudget) {
					t.Errorf("catalog escaped budget (nat=%v): %v", natOnly, err)
				}
				if allocated := end.TotalAlloc - start.TotalAlloc; allocated > 64<<10 {
					t.Errorf("over-budget catalog was copied (nat=%v): %d bytes", natOnly, allocated)
				}
			} else if err != nil {
				t.Errorf("adequate budget (nat=%v): %v", natOnly, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := check(ctx); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		}
	}
	// No NAT means no catalog comparison is required, even on a large graph.
	d.StaticNATs = nil
	withoutNAT, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := (policy.Engine{Limits: policy.Limits{MaxVisits: 1}}).PreserveNAT(context.Background(), withoutNAT, withoutNAT, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestEquivalenceBudgetsNATOwnersOnceAcrossContexts(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}}
	for i := range 10 {
		d.Zones = append(d.Zones, fm.ZoneRecord{Object: fm.Object{ID: fm.ID(fmt.Sprintf("zone-%d", i))}})
	}
	for i := range 100 {
		d.DynamicNATs = append(d.DynamicNATs, fm.DynamicNATRecord{
			Object: fm.Object{ID: fm.ID(fmt.Sprintf("nat-%d", i))}, Disabled: true,
			Match: anyMatch(), SourceMode: fm.NoTranslation, DestinationMode: fm.NoTranslation,
		})
	}
	fw, err := fm.Seal(d)
	if err != nil || !fw.Complete() {
		t.Fatalf("fixture: %v", err)
	}
	for _, limit := range []int{220, 420} {
		proof, err := (policy.Engine{Limits: policy.Limits{MaxVisits: limit}}).Equivalent(context.Background(), fw, fw, time.Time{})
		if limit == 220 {
			if !errors.Is(err, policy.ErrBudget) || proof.BaseDigest != "" {
				t.Errorf("NAT ownership scan escaped preparation budget: %+v %v", proof, err)
			}
		} else if err != nil || proof.Contexts != 100 {
			t.Fatalf("NAT ownership index was rebuilt per context: %+v %v", proof, err)
		}
	}
}
