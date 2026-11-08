// Package hillstone implements scoped StoneOS configuration parsing.
package hillstone

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

const ParserVersion = "hillstone-go-7"

type parser struct {
	doc      *document
	catalog  catalog
	topology topology
}

type Parser struct {
	Limits config.Limits
	// Services supplies an observed predefined service book. Configuration
	// declarations take precedence; the parser never consults a database.
	Services []fm.ServiceRecord
}

func (opts Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor = "hillstone"
	metadata.ParserVersion = ParserVersion
	content, err := config.NewContent(ctx, source, opts.Limits)
	if err != nil {
		return nil, err
	}
	doc, err := readDocument(ctx, content)
	if err != nil {
		return nil, err
	}
	builder, err := config.NewBuilder(content, metadata)
	if err != nil {
		return nil, err
	}
	p := parser{
		doc: doc,
		catalog: catalog{
			doc: doc, addresses: make(map[fm.ID]fm.Kind),
			services: make(map[fm.ID]fm.Kind), book: opts.Services,
		},
		topology: topology{doc: doc, zoneVRF: make(map[fm.ID]string)},
	}
	if err := builder.Phase(ctx, "structure", doc.structure); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "zones", p.topology.zones); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "interfaces", p.topology.interfaces); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "objects", p.catalog.parse); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "routes", p.topology.routes); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "rules", p.rules); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "nat", p.nat); err != nil {
		return nil, err
	}
	return builder.Seal()
}
