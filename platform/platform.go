// Package platform bundles what Firemon knows of each vendor's syntax and
// device behaviour: parsing, rendering, deploy commands, capabilities,
// naming, predefined services, hit counters and HA roles. It does no I/O,
// so a backend can use it as the CLI does.
package platform

import (
	"cmp"
	"errors"
	"fmt"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/design"
	"github.com/gatework/firemon/hits"
	"github.com/gatework/firemon/migrate"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/paloalto"
)

// ErrVendor reports a vendor Firemon does not support.
var ErrVendor = errors.New("platform: unsupported vendor")

// Platform is one vendor's syntax and device behaviour.
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
	// HAStateCommand is the read-only command whose output tells the HA
	// role when the prompt does not; empty when the prompt always does.
	HAStateCommand string
	// HARole reads the runtime HA role from the device prompt and the
	// output of HAStateCommand.
	HARole func(prompt, output string) firemon.HARole
	// Capabilities describe what the vendor's configuration expresses.
	Capabilities firemon.Capabilities
}

// Options configure a platform.
type Options struct {
	// Location is the time zone schedules are read in; nil is UTC, or the
	// zone the configuration sets.
	Location *time.Location
	// Services, when not nil, is the predefined service book observed on
	// the device; it overrides the vendor default.
	Services firemon.ServiceBook
}

// Vendors are the supported vendors.
func Vendors() []firemon.Vendor {
	return []firemon.Vendor{firemon.VendorHillstone, firemon.VendorPaloAlto}
}

// For returns the platform of vendor.
func For(vendor firemon.Vendor, opts Options) (Platform, error) {
	switch vendor {
	case firemon.VendorHillstone:
		p := hillstone.New(hillstone.Options{Location: opts.Location, Services: opts.Services})
		return Platform{
			Vendor: vendor, Services: hillstone.DefaultServices().With(opts.Services), Applications: hillstone.DefaultApplications(),
			Parse: p.Parse, Render: hillstone.Renderer{}.Render, DeployCommands: hillstone.DeployCommands,
			HitCountCommand: hillstone.HitCountCommand, ParseHits: hillstone.ParseHits,
			HARole: hillstone.HARole, Capabilities: hillstone.Capabilities(),
		}, nil
	case firemon.VendorPaloAlto:
		p := paloalto.New(paloalto.Options{Location: opts.Location, Services: opts.Services})
		loc := cmp.Or(opts.Location, time.UTC)
		return Platform{
			Vendor: vendor, Services: paloalto.DefaultServices().With(opts.Services), Applications: paloalto.DefaultApplications(), Naming: paloalto.Naming(),
			Parse: p.Parse, Render: paloalto.Renderer{}.Render, DeployCommands: paloalto.DeployCommands,
			HitCountCommand: paloalto.HitCountCommand,
			ParseHits: func(text, firewall string, taken time.Time) (hits.Snapshot, error) {
				return paloalto.ParseHits(text, firewall, taken, loc)
			},
			HAStateCommand: paloalto.HAStateCommand, HARole: paloalto.HARole, Capabilities: paloalto.Capabilities(),
		}, nil
	case firemon.VendorUnset:
		return Platform{}, fmt.Errorf("%w: vendor required", ErrVendor)
	default:
		return Platform{}, fmt.Errorf("%w: %s", ErrVendor, vendor)
	}
}

// MigrationTarget describes the platform as the target of a migration:
// its default semantics (those of an empty configuration), capabilities,
// name rules and predefined services.
func (p Platform) MigrationTarget() (migrate.Target, error) {
	empty, err := p.Parse("")
	if err != nil {
		return migrate.Target{}, err
	}
	return migrate.Target{
		Vendor: p.Vendor, Semantics: empty.Semantics, Capabilities: p.Capabilities, Sanitize: p.Naming.Sanitize, Services: p.Services,
		Render: p.Render, Parse: p.Parse,
	}, nil
}
