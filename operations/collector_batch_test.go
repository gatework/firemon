package operations_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gatework/firemon/device"
	"github.com/gatework/firemon/operations"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
)

type batchReaders struct {
	mu      sync.Mutex
	readers map[string]*captureDevice
}

func TestCollectBatchKeepsPublishedCompletionWhenCloseFails(t *testing.T) {
	c, store, reader, request := collectionFixture(t)
	reader.closeErr = errors.New("reader close failed")
	collector, err := operations.NewCollector(c.CollectorOptions)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := collector.CollectBatch(t.Context(), []operations.CollectRequest{request}, operations.CollectBatchOptions{})
	if err != nil || len(rows) != 1 || rows[0].Status != "complete" || !rows[0].Result.Published() || !rows[0].Result.Complete || !errors.Is(rows[0].Err, reader.closeErr) {
		t.Fatalf("published completion changed by cleanup: %+v %v", rows, err)
	}
	_, head, err := store.Current(t.Context(), request.Device)
	if err != nil || head.Revision != rows[0].Result.Revision {
		t.Fatalf("publication missing: %v", err)
	}
}

func (b *batchReaders) OpenReadOnly(ctx context.Context, id string) (device.Reader, error) {
	b.mu.Lock()
	d := b.readers[id]
	b.mu.Unlock()
	return d.OpenReadOnly(ctx, id)
}
func TestCollectBatchIsolatesFailuresDuplicatesAndRetries(t *testing.T) {
	c, store, good, req := collectionFixture(t)
	bad := &captureDevice{openErr: errors.New("offline")}
	factory := &batchReaders{readers: map[string]*captureDevice{"fw": good, "bad": bad}}
	c.Sessions = factory
	collector, err := operations.NewCollector(c.CollectorOptions)
	if err != nil {
		t.Fatal(err)
	}
	requests := []operations.CollectRequest{req, {Device: "bad", PublicationID: "bad"}, {Device: "duplicate", PublicationID: "d1"}, {Device: "duplicate", PublicationID: "d2"}}
	rows, err := collector.CollectBatch(context.Background(), requests, operations.CollectBatchOptions{})
	if err != nil || len(rows) != 4 || !rows[0].Result.Complete || !errors.Is(rows[1].Err, bad.openErr) || !errors.Is(rows[2].Err, operations.ErrDuplicateDevice) || !errors.Is(rows[3].Err, operations.ErrDuplicateDevice) {
		t.Fatal(rows, err)
	}
	if good.closes != 1 {
		t.Fatal("session not closed")
	}
	if _, head, e := store.Current(context.Background(), "fw"); e != nil || head.Revision != rows[0].Result.Revision {
		t.Fatal(head, e)
	}
	retry, e := collector.CollectBatch(context.Background(), requests[:1], operations.CollectBatchOptions{})
	if e != nil || retry[0].Err != nil || retry[0].Result != rows[0].Result || good.opens != 1 {
		t.Fatal(retry, e)
	}
}
func TestCollectBatchDefaultWorkersAndCancellationRetainEvidence(t *testing.T) {
	store, err := snapshot.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan string, 8)
	factory := &batchReaders{readers: map[string]*captureDevice{}}
	var requests []operations.CollectRequest
	for i := range 8 {
		id := fmt.Sprint("fw", i)
		_, _, d, _ := collectionFixture(t)
		d.capture.Metadata.Device = id
		d.onRead = func(ctx context.Context) { started <- id; <-ctx.Done() }
		factory.readers[id] = d
		requests = append(requests, operations.CollectRequest{Device: id, PublicationID: id})
	}
	collector, err := operations.NewCollector(operations.CollectorOptions{Store: store, Sessions: factory, Parser: vendors.Parser{}, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan []operations.CollectOutcome, 1)
	go func() {
		rows, _ := collector.CollectBatch(ctx, requests, operations.CollectBatchOptions{})
		done <- rows
	}()
	for range 4 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("workers did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("more than four workers")
	default:
	}
	cancel()
	rows := <-done
	opened := 0
	for i, row := range rows {
		d := factory.readers[requests[i].Device]
		opened += d.opens
		if d.opens > 0 {
			if row.Result.Revision == "" || row.Result.Complete || d.closes != 1 || !errors.Is(row.Err, context.Canceled) {
				t.Fatal(row, d)
			}
		} else if !errors.Is(row.Err, context.Canceled) {
			t.Fatal("unscheduled item missing cancellation", row)
		}
	}
	if opened != 4 {
		t.Fatal("scheduled after cancellation", opened)
	}
}

func TestCollectBatchKeepsCASReservationAndTimeoutIndependent(t *testing.T) {
	c, store, good, req := collectionFixture(t)
	stale := *good
	stale.capture.Metadata.Device = "stale"
	reserved := *good
	reserved.capture.Metadata.Device = "reserved"
	slow := *good
	slow.capture.Metadata.Device = "slow"
	slow.onRead = func(ctx context.Context) { <-ctx.Done() }
	base := parseNative(t, panBase, reserved.capture.Metadata)
	pub, err := store.Publish(context.Background(), base, snapshot.PublishOptions{PublicationID: "reserved-base"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve(context.Background(), "reserved", pub.Revision, "deploy"); err != nil {
		t.Fatal(err)
	}
	c.Sessions = &batchReaders{readers: map[string]*captureDevice{"fw": good, "stale": &stale, "reserved": &reserved, "slow": &slow}}
	c.Timeout = time.Second
	collector, err := operations.NewCollector(c.CollectorOptions)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := collector.CollectBatch(context.Background(), []operations.CollectRequest{req, {Device: "stale", Expected: "wrong", PublicationID: "stale"}, {Device: "reserved", Expected: pub.Revision, PublicationID: "reserved"}, {Device: "slow", PublicationID: "slow"}}, operations.CollectBatchOptions{})
	if err != nil || rows[0].Err != nil || !rows[0].Result.Complete || !errors.Is(rows[1].Err, snapshot.ErrConflict) || !errors.Is(rows[2].Err, snapshot.ErrReserved) || !errors.Is(rows[3].Err, context.DeadlineExceeded) || rows[3].Result.Revision == "" || rows[3].Result.Complete {
		t.Fatal(rows, err)
	}
	if stale.opens != 0 || reserved.opens != 0 || slow.closes != 1 {
		t.Fatal("batch bypassed preflight/session ownership")
	}
}
