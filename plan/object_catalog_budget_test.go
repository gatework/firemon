package plan

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
	"github.com/gatework/firemon/policy"
)

func TestObjectCatalogRestrictsResolutionAfterDirectIndexWork(t *testing.T) {
	const count = 1 << 15
	ip := netip.MustParseAddr("192.0.2.1")
	ranges := make([]flow.AddressRange, count)
	terms := make([]fm.ServiceTerm, count)
	for i := range count {
		ranges[i] = flow.AddressRange{First: ip, Last: ip}
		terms[i] = fm.ServiceTerm{Protocol: flow.Interval{Low: 6, High: 6}, DestinationPort: flow.Interval{Low: uint16(i), High: uint16(i)}}
	}
	fw, err := fm.Seal(fm.Data{
		Metadata:  fm.Metadata{Device: "catalog-budget", Vendor: "hillstone"},
		Addresses: []fm.AddressRecord{{Object: fm.Object{ID: "address"}, Ranges: ranges}},
		Services:  []fm.ServiceRecord{{Object: fm.Object{ID: "service"}, Terms: terms}},
	})
	if err != nil {
		t.Fatal(err)
	}
	data := fw.Export()
	for _, remaining := range []int{0, 1} {
		t.Run(fmt.Sprintf("remaining=%d", remaining), func(t *testing.T) {
			// Two catalog entries, two name reservations and the direct address
			// ranges consume the shared budget before service expansion starts.
			visits := visitBudget(4 + count + remaining)
			limits := policy.Limits{MaxVisits: int(visits), MaxCombinations: count + 1}
			var start, end runtime.MemStats
			runtime.ReadMemStats(&start)
			catalog, err := newObjectCatalog(t.Context(), fw, &data, limits, &visits)
			runtime.ReadMemStats(&end)
			if !errors.Is(err, policy.ErrBudget) || catalog != nil || visits != 0 {
				t.Fatalf("exhausted shared allowance: catalog=%v visits=%d err=%v", catalog != nil, visits, err)
			}
			if allocated := end.TotalAlloc - start.TotalAlloc; allocated > 64<<10 {
				t.Fatalf("service expanded using a stale allowance: %d bytes", allocated)
			}
		})
	}
}
