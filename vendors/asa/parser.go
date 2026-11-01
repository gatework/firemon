// Package asa parses native ASA blocks, ACL bindings and distinct NAT objects.
package asa

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

type block struct {
	header               config.Statement
	kind, name, protocol string
	members              []config.Statement
}
type parser struct {
	builder           *config.Builder
	blocks            []block
	lines             []config.Statement
	graph             *fm.Firewall
	literalIDs        map[fm.ID]bool
	literalCommitted  int
	literalDraft      *fm.Data
	literalDraftCount int
	aliases           map[string]fm.ID
	legacy, modern    bool
}

type Parser struct{ Limits config.Limits }

func Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	return (Parser{}).Parse(ctx, source, metadata)
}

func (native Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor = "asa"
	metadata.ParserVersion = "asa-go-3"
	content, err := config.NewContent(ctx, source, native.Limits)
	if err != nil {
		return nil, err
	}
	statements, err := config.Statements(ctx, content)
	if err != nil {
		return nil, err
	}
	builder, err := config.NewBuilder(content, metadata)
	if err != nil {
		return nil, err
	}
	p := &parser{builder: builder, aliases: make(map[string]fm.ID)}
	if err := p.scan(ctx, statements); err != nil {
		return nil, err
	}
	if err := p.builder.Phase(ctx, "interfaces", p.interfaces); err != nil {
		return nil, err
	}
	if err := p.builder.Phase(ctx, "objects", p.objects); err != nil {
		return nil, err
	}
	if err := p.builder.Phase(ctx, "routes-bindings", p.routes); err != nil {
		return nil, err
	}
	if err := p.builder.Phase(ctx, "acl", p.acls); err != nil {
		return nil, err
	}
	if err := p.builder.Phase(ctx, "nat", p.nat); err != nil {
		return nil, err
	}
	if p.legacy && p.modern {
		tx := p.builder.Begin()
		tx.Emit(fm.Data{Diagnostics: []fm.Diagnostic{{Code: "mixed-nat-generation", Message: "legacy and modern ASA NAT require explicit migration/version evidence"}}})
		if err := p.builder.Commit(tx); err != nil {
			return nil, err
		}
	}
	return p.builder.Seal()
}
