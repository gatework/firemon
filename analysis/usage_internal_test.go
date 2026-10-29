package analysis

import (
	"context"
	"errors"
	"testing"
	"time"

	fm "github.com/gatework/firemon"
)

type cancelUsageContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *cancelUsageContext) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestUsageSortMergesChunksAndStopsOnCancellation(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var windows []fm.TimeWindow
	for i := 255; i >= 0; i-- {
		windows = append(windows, fm.TimeWindow{Start: start.Add(time.Duration(i) * time.Second), End: start.Add(time.Duration(i+1) * time.Second)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interrupted := &cancelUsageContext{Context: ctx, cancel: cancel, remaining: 4}
	evidence := usageEvidence{covered: windows}
	window := fm.TimeWindow{Start: start, End: start.Add(256 * time.Second)}
	if _, err := evidence.unused(interrupted, window); !errors.Is(err, context.Canceled) {
		t.Fatalf("sort ignored cancellation: %v", err)
	}
	value, err := evidence.unused(context.Background(), window)
	if err != nil || value != True {
		t.Fatalf("cross-chunk coverage lost: %v %v", value, err)
	}
}

func TestIncompleteReclamationStillChecksCancellation(t *testing.T) {
	d := fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "hillstone"}, Diagnostics: []fm.Diagnostic{{Code: "incomplete"}}}
	for _, id := range []fm.ID{"1", "2", "3", "4"} {
		d.Rules = append(d.Rules, fm.RuleRecord{Object: fm.Object{ID: id}, RuleSet: "security", Action: fm.Permit, Match: fm.Match{AnySource: true, AnyDestination: true, AnyService: true, AnyFromZone: true, AnyToZone: true}})
	}
	fw, err := fm.Seal(d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	interrupted := &cancelUsageContext{Context: ctx, cancel: cancel, remaining: 5}
	rows, err := (Reclaimer{}).Analyze(interrupted, fw, ReclamationRequest{})
	if !errors.Is(err, context.Canceled) || rows != nil {
		t.Fatalf("partial output on cancellation: %v %v", rows, err)
	}
}
