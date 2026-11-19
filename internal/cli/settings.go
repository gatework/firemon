package cli

import (
	"cmp"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gatework/firemon/adapter/yamlfile"
)

// Environment variables that set defaults for the shared flags.
const (
	envConfig    = "FIREMON_CONFIG"    // settings file
	envStore     = "FIREMON_STORE"     // --store
	envInventory = "FIREMON_INVENTORY" // --inventory
	envTimezone  = "FIREMON_TIMEZONE"  // --timezone
)

// resolveDefaults fills the shared flags the command line left unset, in
// order: environment, the inventory's store, the settings file, built-in
// defaults. Everyday queries then need no flags at all.
func (o *options) resolveDefaults(cmd *cobra.Command) error {
	getenv := o.deps.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	settings, err := yamlfile.LoadSettings(cmp.Or(getenv(envConfig), defaultSettingsPath()))
	if err != nil {
		return &usageError{err}
	}
	flags := cmd.Flags()
	if !flags.Changed("inventory") {
		o.inventoryFile = expandHome(cmp.Or(getenv(envInventory), settings.Inventory))
	}
	if !flags.Changed("timezone") {
		o.timezone = cmp.Or(getenv(envTimezone), settings.Timezone, "Local")
	}
	if !flags.Changed("store") {
		o.store = cmp.Or(expandHome(getenv(envStore)), o.inventoryStore(), expandHome(settings.Store), defaultStore())
	}
	return nil
}

// inventoryStore is the store the inventory file names, relative to it.
func (o *options) inventoryStore() string {
	if o.inventoryFile == "" {
		return ""
	}
	f, err := yamlfile.Load(o.inventoryFile)
	if err != nil || f.Store == "" {
		return "" // the command reports a bad inventory when it reads it
	}
	store := expandHome(f.Store)
	if filepath.IsAbs(store) {
		return store
	}
	return filepath.Join(filepath.Dir(o.inventoryFile), store)
}

func defaultSettingsPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "firemon", "config.yaml")
}

// expandHome expands a leading "~/".
func expandHome(path string) string {
	rest, ok := strings.CutPrefix(path, "~/")
	if !ok {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, rest)
}
