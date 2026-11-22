package bootstrap

import (
	"cmp"
	"fmt"
	"time"

	"github.com/gatework/netops/store"
	"github.com/gatework/netops/store/journal"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/adapter/filestore"
	"github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/hits"
	"github.com/gatework/firemon/migrate"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/paloalto"
)

// Platform bundles one vendor's syntax capabilities.
type Platform struct {
	Vendor firemon.Vendor
	// Services is the effective predefined service book: the vendor default
	// overridden by the device book.
	Services       firemon.ServiceBook
	Applications   firemon.ServiceBook
	Naming         design.Naming
	Parse          func(text string) (*firemon.Config, error)
	Render         func(plan *design.Plan) (design.Script, error)
	DeployCommands func(script design.Script) []string
	// HitCountCommand reads the rule hit counters; ParseHits reads its
	// output.
	HitCountCommand string
	ParseHits       func(text, firewall string, taken time.Time) (hits.Snapshot, error)
	// Capabilities describe what the vendor's configuration expresses.
	Capabilities firemon.Capabilities
}

// MigrationTarget describes the platform as the target of a migration:
// its default semantics (those of an empty configuration), capabilities,
// name rules and predefined services.
func MigrationTarget(p Platform) (migrate.Target, error) {
	empty, err := p.Parse("")
	if err != nil {
		return migrate.Target{}, err
	}
	return migrate.Target{
		Vendor: p.Vendor, Semantics: empty.Semantics, Capabilities: p.Capabilities, Sanitize: p.Naming.Sanitize, Services: p.Services,
		Render: p.Render, Parse: p.Parse,
	}, nil
}

// Lookup returns the platform of vendor with schedules in loc. book, when
// not nil, is the predefined service book observed on the device.
func Lookup(vendor firemon.Vendor, loc *time.Location, book firemon.ServiceBook) (Platform, error) {
	switch vendor {
	case firemon.VendorHillstone:
		p := hillstone.New(hillstone.Options{Location: loc, Services: book})
		return Platform{
			Vendor: vendor, Services: hillstone.DefaultServices().With(book), Applications: hillstone.DefaultApplications(),
			Parse: p.Parse, Render: hillstone.Renderer{}.Render, DeployCommands: hillstone.DeployCommands,
			HitCountCommand: hillstone.HitCountCommand, ParseHits: hillstone.ParseHits, Capabilities: hillstone.Capabilities(),
		}, nil
	case firemon.VendorPaloAlto:
		p := paloalto.New(paloalto.Options{Location: loc, Services: book})
		return Platform{
			Vendor: vendor, Services: paloalto.DefaultServices().With(book), Applications: paloalto.DefaultApplications(), Naming: paloalto.Naming(),
			Parse: p.Parse, Render: paloalto.Renderer{}.Render, DeployCommands: paloalto.DeployCommands,
			HitCountCommand: paloalto.HitCountCommand, Capabilities: paloalto.Capabilities(),
			ParseHits: func(text, firewall string, taken time.Time) (hits.Snapshot, error) {
				return paloalto.ParseHits(text, firewall, taken, cmp.Or(loc, time.UTC))
			},
		}, nil
	case firemon.VendorUnset:
		return Platform{}, fmt.Errorf("bootstrap: vendor required")
	default:
		return Platform{}, fmt.Errorf("bootstrap: unsupported vendor %s", vendor)
	}
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
