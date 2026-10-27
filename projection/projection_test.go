package projection_test

import (
	"context"
	"errors"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/projection"
	"github.com/gatework/firemon/snapshot"
	"testing"
)

type sink struct {
	fail    bool
	applied []projection.Batch
}

func (s *sink) Apply(_ context.Context, b projection.Batch) error {
	if s.fail {
		return errors.New("database offline")
	}
	s.applied = append(s.applied, b)
	return nil
}
func TestFailedProjectionRetainsOutboxAndQueriesUsePublishedFile(t *testing.T) {
	ctx := context.Background()
	store, _ := snapshot.Open(t.TempDir())
	fw, _ := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "test"}, Raw: "not parsed"})
	published, err := store.Publish(ctx, fw, snapshot.PublishOptions{PublicationID: "one"})
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{fail: true}
	if err := projection.Drain(ctx, store, "db", s); err == nil {
		t.Fatal("projection failure lost")
	}
	if _, _, err := store.Current(ctx, "fw"); err != nil {
		t.Fatal("DB outage blocked file queries", err)
	}
	m, _ := store.Manifest(ctx)
	if m.Acknowledged["db"] != 0 {
		t.Fatal("failed batch acknowledged")
	}
	s.fail = false
	if err := projection.Drain(ctx, store, "db", s); err != nil {
		t.Fatal(err)
	}
	if len(s.applied) != 1 || s.applied[0].Revision != published.Revision || s.applied[0].Firewall.Export().Raw != "not parsed" {
		t.Fatal("projection did not load published graph")
	}
	if err := projection.Drain(ctx, store, "db", s); err != nil || len(s.applied) != 1 {
		t.Fatal("acknowledged event replay", err)
	}
}
