package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// TestLayout uses HOME, so it does not run in parallel.
func TestLayout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".gatework")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "firemon.yml"), []byte("timezone: Asia/Shanghai\ninventory: firemon/inventory.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("FIREMON_PASSWORD=file\nFIREMON_ENABLE_PASSWORD=file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	process := map[string]string{"FIREMON_PASSWORD": "process"}
	getenv := func(k string) string { return process[k] }

	if got := gatework(getenv).Discover(); got != filepath.Join(dir, "firemon.yml") {
		t.Errorf("settings discovered at %q", got)
	}
	data := filepath.Join(home, ".local", "share", "gatework", "firemon")
	if got := defaultStore(getenv); got != filepath.Join(data, "snapshots") {
		t.Errorf("store %q", got)
	}
	if got := defaultJournalRoot(getenv); got != filepath.Join(data, "deploy") {
		t.Errorf("journal %q", got)
	}

	o := &options{deps: &Deps{Getenv: getenv}}
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	cmd.Flags().String("inventory", "", "")
	cmd.Flags().String("timezone", "", "")
	cmd.Flags().String("store", "", "")
	if err := o.resolveDefaults(cmd); err != nil {
		t.Fatal(err)
	}
	if o.timezone != "Asia/Shanghai" || o.store != filepath.Join(data, "snapshots") ||
		o.inventoryFile != filepath.Join(dir, "firemon", "inventory.yaml") {
		t.Errorf("defaults timezone=%q store=%q inventory=%q", o.timezone, o.store, o.inventoryFile)
	}
	if got := o.deps.Getenv("FIREMON_PASSWORD"); got != "process" {
		t.Errorf("process environment must win, got %q", got)
	}
	if got := o.deps.Getenv("FIREMON_ENABLE_PASSWORD"); got != "file" {
		t.Errorf("credentials file not overlaid, got %q", got)
	}
}
