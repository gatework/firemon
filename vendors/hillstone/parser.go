// Package hillstone implements scoped StoneOS configuration parsing.
package hillstone

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

const ParserVersion = "hillstone-go-6"

type node struct {
	block           *config.Block
	scope, from, to string
}
type statement struct {
	line  config.Statement
	scope string
}
type parser struct {
	builder      *config.Builder
	document     config.Document
	nodes        []node
	lines        []statement
	zoneVRF      map[fm.ID]string
	addressKinds map[fm.ID]fm.Kind
	serviceKinds map[fm.ID]fm.Kind
	graph        *fm.Firewall
}

type Parser struct{ Limits config.Limits }

func (native Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor = "hillstone"
	metadata.ParserVersion = ParserVersion
	content, err := config.NewContent(ctx, source, native.Limits)
	if err != nil {
		return nil, err
	}
	document, err := config.Blocks(ctx, content, classify)
	if err != nil {
		return nil, err
	}
	builder, err := config.NewBuilder(content, metadata)
	if err != nil {
		return nil, err
	}
	p := &parser{document: document, zoneVRF: make(map[fm.ID]string), addressKinds: make(map[fm.ID]fm.Kind), serviceKinds: make(map[fm.ID]fm.Kind)}
	p.collect(document.Roots, "", "", "")
	for _, line := range document.Lines {
		p.lines = append(p.lines, statement{line: line})
	}
	p.builder = builder
	if err := builder.Phase(ctx, "structure", p.structure); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "zones", p.zones); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "interfaces", p.interfaces); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "objects", p.objects); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "routes", p.routes); err != nil {
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
