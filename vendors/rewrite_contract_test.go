package vendors_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/snapshot"
	"github.com/gatework/firemon/vendors"
	"os"
	"path/filepath"
	"testing"
)

// These canonical graph hashes were produced by the frozen working tree before
// the rewrite, including the previously verified Hillstone corrections. Only
// ParserVersion is normalized; source evidence and native order are compared.
func TestRewritePreservesNativeGraphsAndSnapshots(t *testing.T) {
	raw, err := os.ReadFile("testdata/rewrite/graphs.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for vendor, expected := range want {
		t.Run(vendor, func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join("testdata/rewrite", vendor+".conf"))
			if err != nil {
				t.Fatal(err)
			}
			fw, err := (vendors.Parser{}).Parse(context.Background(), config.Source{Text: string(source), Complete: true}, fm.Metadata{Device: "rewrite-baseline", Vendor: vendor, Software: "7.4.0"})
			if err != nil {
				t.Fatal(err)
			}
			if !fw.Complete() {
				t.Fatal(fw.Diagnostics())
			}
			var encoded bytes.Buffer
			if err := snapshot.Encode(&encoded, fw); err != nil {
				t.Fatal(err)
			}
			restored, err := snapshot.Decode(&encoded, 64<<20)
			if err != nil {
				t.Fatal(err)
			}
			for _, graph := range []*fm.Firewall{fw, restored} {
				data := graph.Export()
				data.Metadata.ParserVersion = "comparison"
				wire, err := json.Marshal(data)
				if err != nil {
					t.Fatal(err)
				}
				if got := fmt.Sprintf("%x", sha256.Sum256(wire)); got != expected {
					t.Fatalf("native graph changed: got %s want %s", got, expected)
				}
			}
			if fw.SemanticDigest() != restored.SemanticDigest() {
				t.Fatal("snapshot changed semantic identity")
			}
		})
	}
}
