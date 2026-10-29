package projection_test

import (
	"context"
	"errors"
	"testing"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/projection"
	"github.com/gatework/firemon/snapshot"
)

type brokenOutbox struct {
	acks  int
	graph *fm.Firewall
}

func (s *brokenOutbox) Manifest(context.Context) (snapshot.Manifest, error) {
	return snapshot.Manifest{Events: []snapshot.Event{{Device: "fw", Revision: "revision", Generation: 1, Complete: true}}}, nil
}
func (s *brokenOutbox) Load(context.Context, string) (*fm.Firewall, error) { return s.graph, nil }
func (s *brokenOutbox) Acknowledge(context.Context, string, uint64, uint64) error {
	s.acks++
	return nil
}
func TestProjectionBrokenProvidersNeverAcknowledge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := projection.Drain(ctx, nil, "", nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var nilBox *brokenOutbox
	var typedSink *sink
	box := &brokenOutbox{}
	for _, request := range []struct {
		name  string
		store projection.Outbox
		sink  projection.Sink
	}{
		{name: "db", sink: &sink{}},
		{name: "db", store: nilBox, sink: &sink{}},
		{store: box, sink: &sink{}},
		{name: "db", store: box},
		{name: "db", store: box, sink: typedSink},
	} {
		if err := projection.Drain(context.Background(), request.store, request.name, request.sink); !errors.Is(err, projection.ErrInvalid) || errors.Is(err, snapshot.ErrFormat) {
			t.Fatal("invalid projection argument classification", err)
		}
	}
	live := &sink{}
	if err := projection.Drain(context.Background(), box, "db", live); !errors.Is(err, snapshot.ErrFormat) || box.acks != 0 || len(live.applied) != 0 {
		t.Fatal("nil graph projected or acknowledged", err)
	}
}

func TestProjectionMismatchedGraphRemainsFormatError(t *testing.T) {
	graph, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "another-device", Vendor: "test"}})
	if err != nil {
		t.Fatal(err)
	}
	box := &brokenOutbox{graph: graph}
	live := &sink{}
	err = projection.Drain(context.Background(), box, "db", live)
	if !errors.Is(err, snapshot.ErrFormat) || errors.Is(err, projection.ErrInvalid) || box.acks != 0 || len(live.applied) != 0 {
		t.Fatal("malformed graph projected or classification changed", err)
	}
}
