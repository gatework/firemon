package main

import (
	"bytes"
	"context"
	"encoding/json"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/snapshot"
	"testing"
)

func TestHistoricalInspectReportsRequestedRevision(t *testing.T) {
	root := t.TempDir()
	store, err := snapshot.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	fw, err := fm.Seal(fm.Data{Metadata: fm.Metadata{Device: "fw", Vendor: "test"}, Raw: "historical"})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.Archive(context.Background(), fw)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"inspect", "--store", root, "--revision", revision}, &out); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Revision != revision {
		t.Fatalf("revision=%q want %q", got.Revision, revision)
	}
}
