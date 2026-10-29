package snapshot_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/gatework/firemon/snapshot"
)

// Generated from synthetic DTOs at bc15a8b, before the domain type renames.
// Keep these bytes frozen: re-encoding with current types defeats this test.
func TestPreDomainNamesSnapshotRemainsReadable(t *testing.T) {
	encoded, err := os.ReadFile("testdata/pre-domain-names-v9.gob")
	if err != nil {
		t.Fatal(err)
	}
	fw, err := snapshot.Decode(bytes.NewReader(encoded), snapshot.DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	const digest = "68e7722ee9b389caa6de70494a25ffdf21f76831e81e4294394432cecccd0e49"
	if fw.SemanticDigest() != digest {
		t.Fatalf("semantic digest changed: %s", fw.SemanticDigest())
	}
	if fw.Address("host").Record().Ranges[0].First.String() != "192.0.2.1" ||
		len(fw.Export().Routes[0].PolicyMatch) != 1 || fw.StaticNAT("static") == nil || fw.DynamicNAT("dynamic") == nil {
		t.Fatal("snapshot lost typed traffic or NAT data")
	}
	var current bytes.Buffer
	if err := snapshot.Encode(&current, fw); err != nil {
		t.Fatal(err)
	}
	restored, err := snapshot.Decode(&current, snapshot.DefaultMaxBytes)
	if err != nil || restored.SemanticDigest() != digest {
		t.Fatal("roundtrip changed semantics", err)
	}
}
