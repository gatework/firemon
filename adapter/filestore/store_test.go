package filestore_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/vendors/hillstone"
)

func TestStore_SaveLoad(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "vendors", "hillstone", "testdata", "basic.conf"))
	if err != nil {
		t.Fatal(err)
	}
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Skip("no time zone database")
	}
	cfg, err := hillstone.New(hillstone.Options{Location: loc}).Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	s, err := filestore.New(filepath.Join(t.TempDir(), "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	saved, err := s.Save(t.Context(), filestore.Snapshot{Device: "fw1", Host: "192.0.2.1", CollectedAt: time.Unix(0, 0).UTC(), Config: cfg, Raw: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load(t.Context(), "fw1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint != saved.Fingerprint || loaded.Config.Location.String() != "Asia/Shanghai" || len(loaded.Config.Rules) != len(cfg.Rules) {
		t.Fatalf("loaded %+v", loaded)
	}
	text, err := s.Raw(t.Context(), "fw1")
	if err != nil || text != string(raw) {
		t.Fatalf("raw: %v", err)
	}
	list, err := s.List(t.Context())
	if err != nil || len(list) != 1 || list[0].Device != "fw1" {
		t.Fatalf("list %v %v", list, err)
	}
}

func TestStore_Errors(t *testing.T) {
	t.Parallel()
	s, err := filestore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(t.Context(), "missing"); !errors.Is(err, filestore.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	if _, err := s.Load(t.Context(), "../etc"); !errors.Is(err, filestore.ErrInvalidName) {
		t.Errorf("traversal: %v", err)
	}
}

// A snapshot stored by another model version is reported stale, with its
// metadata, so the caller parses the raw text again.
func TestStore_StaleModel(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "vendors", "hillstone", "testdata", "basic.conf"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := hillstone.New(hillstone.Options{}).Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "snapshots")
	s, err := filestore.New(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(t.Context(), filestore.Snapshot{Device: "fw1", Config: cfg, Raw: string(raw)}); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(root, "fw1", "meta.json")
	body, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	old := strings.Replace(string(body), fmt.Sprintf(`"model": %d`, firemon.ModelVersion), `"model": 1`, 1)
	if err := os.WriteFile(meta, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Load(t.Context(), "fw1")
	if !errors.Is(err, filestore.ErrStale) || snap.Vendor != firemon.VendorHillstone {
		t.Fatalf("stale snapshot: %v %+v", err, snap)
	}
}
