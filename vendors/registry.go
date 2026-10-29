// Package vendors selects the enabled native parsers and command renderers.
// It does not own transport, inventory, or device credentials.
package vendors

import (
	"context"
	"errors"
	"slices"

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
	aliases        []string
	parser         func(config.Limits) config.Parser
	renderer       plan.Renderer
	defaultContext string
}

var definitions = []definition{
	{
		name: "paloalto", aliases: []string{"palo_alto"}, renderer: paloalto.Renderer{},
		parser: func(l config.Limits) config.Parser { return paloalto.Parser{Limits: l} },
	},
	{
		name: "srx", renderer: srx.Renderer{},
		parser: func(l config.Limits) config.Parser { return srx.Parser{Limits: l} },
	},
	{
		name: "huawei", renderer: huawei.Renderer{},
		parser: func(l config.Limits) config.Parser { return huawei.Parser{Limits: l} },
	},
	{
		name: "hillstone", renderer: hillstone.Renderer{},
		parser: func(l config.Limits) config.Parser { return hillstone.Parser{Limits: l} },
	},
	{
		name: "fortinet", renderer: fortinet.Renderer{}, defaultContext: "root",
		parser: func(l config.Limits) config.Parser { return fortinet.Parser{Limits: l} },
	},
	{
		name: "netscreen", aliases: []string{"screenos"}, renderer: netscreen.Renderer{},
		parser: func(l config.Limits) config.Parser { return netscreen.Parser{Limits: l} },
	},
	{
		name: "asa", renderer: asa.Renderer{},
		parser: func(l config.Limits) config.Parser { return asa.Parser{Limits: l} },
	},
}

func lookup(name string) (definition, error) {
	for _, d := range definitions {
		if d.name == name || slices.Contains(d.aliases, name) {
			return d, nil
		}
	}
	return definition{}, ErrUnsupported
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
type Parser struct{ Limits config.Limits }

func (p Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := lookup(metadata.Vendor)
	if err != nil {
		return nil, err
	}
	metadata = d.metadata(metadata)
	return d.parser(p.Limits).Parse(ctx, source, metadata)
}

// Renderer returns the native renderer for an enabled vendor or existing alias.
func Renderer(vendor string) (plan.Renderer, error) {
	d, err := lookup(vendor)
	if err != nil {
		return nil, err
	}
	return d.renderer, nil
}
