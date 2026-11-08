package firemon_test

import (
	"reflect"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/flow"
)

// Canonicalization sorts, trims, clears spans and merges windows; none of it
// may reach the sealed declaration that Export and every view read.
func TestSemanticDigestLeavesSealedDeclarationIntact(t *testing.T) {
	zone := time.FixedZone("synthetic", 3*3600)
	at := func(hour int) time.Time { return time.Date(2026, 1, 2, hour, 0, 0, 0, zone) }
	input := fm.Data{
		Metadata: fm.Metadata{Device: "synthetic", Vendor: "huawei"},
		Addresses: []fm.AddressRecord{
			{
				Object: fm.Object{ID: "z-host", Spans: []fm.Span{{First: 9, Last: 9}}},
				Ranges: []flow.AddressRange{rng("192.0.2.9", "192.0.2.9")},
			},
			{
				Object: fm.Object{ID: "a-orphan", Inline: true, Spans: []fm.Span{{First: 3, Last: 3}}},
				Ranges: []flow.AddressRange{rng("192.0.2.3", "192.0.2.3")},
			},
		},
		Schedules: []fm.ScheduleRecord{{
			Object:  fm.Object{ID: "window", Spans: []fm.Span{{First: 5, Last: 6}}},
			Windows: []fm.TimeWindow{{Start: at(10), End: at(12)}, {Start: at(8), End: at(11)}},
		}},
	}
	expected := input.Clone()
	fw, err := fm.Seal(input)
	if err != nil {
		t.Fatal(err)
	}
	if got := fw.Export(); !reflect.DeepEqual(got, expected) {
		t.Fatalf("sealed declaration changed:\n got %+v\nwant %+v", got, expected)
	}
	if !reflect.DeepEqual(input.Clone(), expected) {
		t.Fatal("Seal changed its caller's data")
	}
}
