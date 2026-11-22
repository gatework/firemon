package cli

import (
	"cmp"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	nbootstrap "github.com/gatework/netops/bootstrap"

	"github.com/gatework/firemon/adapter/yamlfile"
)

// Environment variables that set defaults for the shared flags.
const (
	envConfig    = "FIREMON_CONFIG"    // settings file
	envStore     = "FIREMON_STORE"     // --store
	envInventory = "FIREMON_INVENTORY" // --inventory
	envTimezone  = "FIREMON_TIMEZONE"  // --timezone
)

// app is firemon's name in the shared gatework layout (netops bootstrap):
// settings in ~/.gatework/firemon.yml, credentials in ~/.gatework/.env,
// data under ~/.local/share/gatework/firemon.
const app = "firemon"

// resolveDefaults fills the shared flags the command line left unset, in
// order: environment, the inventory's store, the settings file, built-in
// defaults. Everyday queries then need no flags at all. It also overlays
// the credentials file beside the settings file under the process
// environment, so FIREMON_PASSWORD may live in ~/.gatework/.env.
func (o *options) resolveDefaults(cmd *cobra.Command) error {
	getenv := o.deps.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	layout := gatework(getenv)
	path := layout.Discover()
	settings, err := yamlfile.LoadSettings(path)
	if err != nil {
		return &usageError{err}
	}
	if err := o.overlayCredentials(cmd.Context(), cmp.Or(path, layout.ConfigPath()), getenv); err != nil {
		return &usageError{err}
	}
	// Relative paths in the settings file are relative to it, as in every
	// gatework tool.
	settings.Inventory = relativeTo(path, expandHome(settings.Inventory))
	settings.Store = relativeTo(path, expandHome(settings.Store))
	o.logSetting = settings.LogSetting
	flags := cmd.Flags()
	o.inventoryDefault = expandHome(cmp.Or(getenv(envInventory), settings.Inventory))
	if !flags.Changed("inventory") {
		o.inventoryFile = o.inventoryDefault
	}
	if !flags.Changed("timezone") {
		o.timezone = cmp.Or(getenv(envTimezone), settings.Timezone)
		// Nothing chosen: the configuration's own time zone, else local.
		o.timezoneDefault = o.timezone == ""
		o.timezone = cmp.Or(o.timezone, "Local")
	}
	if !flags.Changed("store") {
		o.store = cmp.Or(expandHome(getenv(envStore)), o.inventoryStore(), expandHome(settings.Store), defaultStore(getenv))
	}
	return nil
}

// overlayCredentials makes o.deps.Getenv fall back to the .env file beside
// the settings file; the process environment still wins. A missing file is
// fine; one readable by group or others is refused.
func (o *options) overlayCredentials(ctx context.Context, settingsPath string, getenv func(string) string) error {
	if settingsPath == "" {
		return nil
	}
	file, err := nbootstrap.LoadEnv(ctx, "", settingsPath, nil)
	if err != nil || len(file) == 0 {
		return err
	}
	o.deps.Getenv = func(name string) string { return cmp.Or(getenv(name), file[name]) }
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

// gatework returns firemon's place in the shared layout.
func gatework(getenv func(string) string) nbootstrap.Env {
	home, _ := os.UserHomeDir()
	environ := map[string]string{}
	if v := getenv(envConfig); v != "" {
		environ[envConfig] = v
	}
	return nbootstrap.Env{App: app, Environ: environ, Home: home}
}

// dataDir is a directory under ~/.local/share/gatework/firemon, or
// fallback (relative to the working directory) without a home directory.
func dataDir(getenv func(string) string, name, fallback string) string {
	if root := gatework(getenv).DataDir(); root != "" {
		return filepath.Join(root, name)
	}
	return fallback
}

// relativeTo resolves a relative path against the directory of file.
func relativeTo(file, path string) string {
	if path == "" || file == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(filepath.Dir(file), path)
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
