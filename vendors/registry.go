// Package vendors selects the enabled native parsers and command renderers.
// It does not own transport, inventory, or device credentials.
package vendors

import (
	"context"
	"errors"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/plan"
	"github.com/gatework/firemon/vendors/asa"
	"github.com/gatework/firemon/vendors/fortinet"
	"github.com/gatework/firemon/vendors/hillstone"
	"github.com/gatework/firemon/vendors/huawei"
	"github.com/gatework/firemon/vendors/netscreen"
	"github.com/gatework/firemon/vendors/paloalto"
	"github.com/gatework/firemon/vendors/srx"
)

var ErrUnsupported = errors.New("vendor has no enabled native implementation")

type definition struct {
	name           string
	parse          func(context.Context, config.Source, fm.Metadata) (*fm.Firewall, error)
	renderer       plan.Renderer
	defaultContext string
}

func lookup(name string) (definition, error) {
	switch name {
	case "paloalto", "palo_alto":
		return definition{name: "paloalto", parse: paloalto.Parse, renderer: paloalto.Renderer{}}, nil
	case "srx":
		return definition{name: "srx", parse: srx.Parse, renderer: srx.Renderer{}}, nil
	case "huawei":
		return definition{name: "huawei", parse: huawei.Parse, renderer: huawei.Renderer{}}, nil
	case "hillstone":
		return definition{name: "hillstone", parse: hillstone.Parse, renderer: hillstone.Renderer{}}, nil
	case "fortinet":
		return definition{name: "fortinet", parse: func(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
			return fortinet.ParseVDOM(ctx, source, metadata, metadata.Context)
		}, renderer: fortinet.Renderer{}, defaultContext: "root"}, nil
	case "netscreen", "screenos":
		return definition{name: "netscreen", parse: netscreen.Parse, renderer: netscreen.Renderer{}}, nil
	case "asa":
		return definition{name: "asa", parse: asa.Parse, renderer: asa.Renderer{}}, nil
	default:
		return definition{}, ErrUnsupported
	}
}

func (d definition) metadata(m fm.Metadata) fm.Metadata {
	m.Vendor = d.name
	if m.Context == "" {
		m.Context = d.defaultContext
	}
	return m
}

// Normalize resolves the existing native vendor aliases and selected-domain
// defaults. Other capture metadata is retained without inventing evidence.
func Normalize(metadata fm.Metadata) (fm.Metadata, error) {
	d, err := lookup(metadata.Vendor)
	if err != nil {
		return fm.Metadata{}, err
	}
	return d.metadata(metadata), nil
}

// Parser dispatches from Metadata.Vendor. Metadata.Context selects the Fortinet
// VDOM; an empty context selects root. Its zero value is ready for use.
type Parser struct{}

func (Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := lookup(metadata.Vendor)
	if err != nil {
		return nil, err
	}
	return d.parse(ctx, source, d.metadata(metadata))
}

// Renderer returns the native renderer for an enabled vendor or existing alias.
func Renderer(vendor string) (plan.Renderer, error) {
	d, err := lookup(vendor)
	if err != nil {
		return nil, err
	}
	return d.renderer, nil
}
