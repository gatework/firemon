package oracle_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatework/firemon"
)

// TestSnapshotRoundTrip_Corpus checks that every configuration survives
// the JSON form snapshots are stored in.
func TestSnapshotRoundTrip_Corpus(t *testing.T) {
	t.Parallel()
	dir := os.Getenv("FIREMON_CORPUS")
	if dir == "" {
		t.Skip("FIREMON_CORPUS not set")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			d, ok := loadDevice(t, path)
			if !ok {
				t.Skip("not a firewall configuration")
			}
			raw, err := json.Marshal(d.fw.Config())
			if err != nil {
				t.Fatal(err)
			}
			var back firemon.Config
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatalf("stored snapshot does not load: %v", err)
			}
			fw, err := firemon.Compile(&back)
			if err != nil {
				t.Fatal(err)
			}
			if fw.Fingerprint() != d.fw.Fingerprint() {
				t.Fatal("stored snapshot differs from the configuration")
			}
		})
	}
}
