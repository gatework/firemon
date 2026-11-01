// Package huawei parses scoped USG configuration through dependency-ordered stages.
package huawei

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

type parser struct {
	builder   *config.Builder
	blocks    []*config.Block
	lines     []config.Statement
	addresses map[string]fm.AddressRef
	services  map[string]fm.ServiceRef
}

// Parse imports a complete current-configuration capture. Unknown native blocks
// stay opaque until their # boundary, including text resembling supported commands.
type Parser struct{ Limits config.Limits }

func Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	return (Parser{}).Parse(ctx, source, metadata)
}

func (native Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor, metadata.ParserVersion = "huawei", "huawei-go-3"
	content, err := config.NewContent(ctx, source, native.Limits)
	if err != nil {
		return nil, err
	}
	rows, err := config.Statements(ctx, content)
	if err != nil {
		return nil, err
	}
	p := &parser{addresses: make(map[string]fm.AddressRef), services: make(map[string]fm.ServiceRef)}
	if err := p.scan(ctx, rows); err != nil {
		return nil, err
	}
	s, err := config.NewBuilder(content, metadata)
	if err != nil {
		return nil, err
	}
	p.builder = s
	if err := s.Phase(ctx, "interfaces-zones", p.network); err != nil {
		return nil, err
	}
	if err := s.Phase(ctx, "routes", p.routes); err != nil {
		return nil, err
	}
	if err := s.Phase(ctx, "objects", p.objects); err != nil {
		return nil, err
	}
	if err := s.Phase(ctx, "policies", p.policies); err != nil {
		return nil, err
	}
	if err := s.Phase(ctx, "nat", p.nat); err != nil {
		return nil, err
	}
	if err := s.Phase(ctx, "evidence", p.evidence); err != nil {
		return nil, err
	}
	return s.Seal()
}

func object(name string) fm.Object { return fm.Object{ID: fm.ID(name), Name: name} }
func (p *parser) commit(s *config.Builder, tx *config.Transaction, d fm.Data) error {
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	return nil
}

type namedBlocks struct {
	name, kind string
	blocks     []*config.Block
}
