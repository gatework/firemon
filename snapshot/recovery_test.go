package snapshot_test

import (
	"context"
	"errors"
	"github.com/gatework/firemon/snapshot"
	"testing"
)

func TestArchiveRetainsEvidenceWithoutChangingCurrentOrOutbox(t *testing.T) {
	ctx := context.Background()
	s, _ := snapshot.Open(t.TempDir())
	base, err := s.Publish(ctx, graph(t, "fw", "base", true), snapshot.PublishOptions{PublicationID: "base"})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := s.Archive(ctx, graph(t, "fw", "observed", true))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load(ctx, revision)
	if err != nil || loaded.Export().Raw != "observed" {
		t.Fatal("lost archived evidence", err)
	}
	m, err := s.Manifest(ctx)
	if err != nil || m.Devices["fw"].Revision != base.Revision || len(m.Events) != 1 {
		t.Fatal("archive published", err)
	}
}

func TestIncompleteRecoveryPublicationRetainsAndAdvancesReservation(t *testing.T) {
	ctx := context.Background()
	s, _ := snapshot.Open(t.TempDir())
	base, err := s.Publish(ctx, graph(t, "fw", "base", true), snapshot.PublishOptions{PublicationID: "base"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Reserve(ctx, "fw", base.Revision, "operation"); err != nil {
		t.Fatal(err)
	}
	opts := snapshot.PublishOptions{Expected: base.Revision, PublicationID: "observation", Reservation: "operation", Live: true, KeepReservation: true}
	observed, err := s.Publish(ctx, graph(t, "fw", "partial", false), opts)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := s.Manifest(ctx)
	if m.Reservations["fw"].Token != "operation" || m.Reservations["fw"].Expected != observed.Revision {
		t.Fatal("uncertain state released ownership")
	}
	if _, _, err := s.Current(ctx, "fw"); !errors.Is(err, snapshot.ErrUnavailable) {
		t.Fatal("uncertain state became current", err)
	}
	opts.KeepReservation = false
	if _, err := s.Publish(ctx, graph(t, "fw", "partial", false), opts); !errors.Is(err, snapshot.ErrConflict) {
		t.Fatal("idempotency changed reservation semantics", err)
	}
	if err := s.ReleaseUnchanged(ctx, "fw", "operation", observed.Revision); !errors.Is(err, snapshot.ErrUnavailable) {
		t.Fatal("incomplete state released as unchanged", err)
	}
	if _, err := s.Publish(ctx, graph(t, "fw", "confirmed", true), snapshot.PublishOptions{Expected: observed.Revision, Reservation: "operation", PublicationID: "confirmed", Live: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Current(ctx, "fw"); err != nil {
		t.Fatal(err)
	}
}
