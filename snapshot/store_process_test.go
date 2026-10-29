package snapshot_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/gatework/firemon/snapshot"
)

func TestReservationFromSeparateProcessIsVisible(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := snapshot.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Publish(ctx, graph(t, "fw", "base", true), snapshot.PublishOptions{PublicationID: "base"})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestReservationHelper$")
	command.Env = append(os.Environ(), "FIREMON_TEST_STORE="+dir, "FIREMON_TEST_REVISION="+first.Revision)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("helper failed: %v %s", err, output)
	}
	if _, _, err := store.Current(ctx, "fw"); !errors.Is(err, snapshot.ErrUnavailable) {
		t.Fatal("another process reservation not observed", err)
	}
}
func TestReservationHelper(t *testing.T) {
	dir := os.Getenv("FIREMON_TEST_STORE")
	if dir == "" {
		t.Skip("subprocess helper")
	}
	store, err := snapshot.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Reserve(context.Background(), "fw", os.Getenv("FIREMON_TEST_REVISION"), "other-process"); err != nil {
		t.Fatal(err)
	}
}
