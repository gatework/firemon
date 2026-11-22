package bootstrap

import (
	"time"

	"github.com/gatework/netops/store"
	"github.com/gatework/netops/store/journal"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/migrate"
	"github.com/gatework/firemon/platform"
)

// Platform bundles one vendor's syntax capabilities (package platform).
type Platform = platform.Platform

// MigrationTarget describes the platform as the target of a migration.
func MigrationTarget(p Platform) (migrate.Target, error) { return p.MigrationTarget() }

// Lookup returns the platform of vendor with schedules in loc. book, when
// not nil, is the predefined service book observed on the device.
func Lookup(vendor firemon.Vendor, loc *time.Location, book firemon.ServiceBook) (Platform, error) {
	return platform.For(vendor, platform.Options{Location: loc, Services: book})
}

// OpenSnapshots opens the private device snapshot store.
func OpenSnapshots(root string) (*filestore.Store, error) {
	return filestore.New(root, netconnector.PrivateFiles{})
}

// Journal returns a deployment journal in a new private batch directory
// under root, and that directory.
func Journal(root string) (*journal.Journal, string, error) {
	s, err := store.NewBatch(root, time.Now())
	if err != nil {
		return nil, "", err
	}
	j, err := journal.Open(s.Root(), nil)
	if err != nil {
		return nil, "", err
	}
	return j, s.Root(), nil
}
