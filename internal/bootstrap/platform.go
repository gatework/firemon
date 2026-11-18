package bootstrap

import (
	"fmt"
	"time"

	"github.com/gatework/go-netops/apply"
	"github.com/gatework/go-netops/store"
	"github.com/gatework/net-connector/connector"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/adapter/netconnector"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/paloalto"
)

// Platform bundles one vendor's syntax capabilities.
type Platform struct {
	Vendor firemon.Vendor
	// Services is the effective predefined service book: the vendor default
	// overridden by the device book.
	Services       firemon.ServiceBook
	Naming         design.Naming
	Parse          func(text string) (*firemon.Config, error)
	Render         func(plan *design.Plan) (design.Script, error)
	DeployCommands func(script design.Script) []string
}

// Lookup returns the platform of vendor with schedules in loc. book, when
// not nil, is the predefined service book observed on the device.
func Lookup(vendor firemon.Vendor, loc *time.Location, book firemon.ServiceBook) (Platform, error) {
	switch vendor {
	case firemon.VendorHillstone:
		p := hillstone.New(hillstone.Options{Location: loc, Services: book})
		return Platform{
			Vendor: vendor, Services: hillstone.DefaultServices().With(book),
			Parse: p.Parse, Render: hillstone.Renderer{}.Render, DeployCommands: hillstone.DeployCommands,
		}, nil
	case firemon.VendorPaloAlto:
		p := paloalto.New(paloalto.Options{Location: loc, Services: book})
		return Platform{
			Vendor: vendor, Services: paloalto.DefaultServices().With(book), Naming: paloalto.Naming(),
			Parse: p.Parse, Render: paloalto.Renderer{}.Render, DeployCommands: paloalto.DeployCommands,
		}, nil
	case firemon.VendorUnset:
		return Platform{}, fmt.Errorf("bootstrap: vendor required")
	default:
		return Platform{}, fmt.Errorf("bootstrap: unsupported vendor %s", vendor)
	}
}

// Client returns a device client for the platform.
func Client(p Platform, conn connector.ConnectionConfig) (*netconnector.Client, error) {
	return netconnector.New(p.Vendor, conn, p.Parse)
}

// Journal returns a deployment journal in a new private batch directory
// under root, and that directory.
func Journal(root string) (apply.Journal, string, error) {
	s, err := store.New(root, store.Options{})
	if err != nil {
		return nil, "", err
	}
	return store.NewJournal(s), s.Directory(), nil
}
