// Package netscreen parses ScreenOS captures using scoped, ordered passes.
package netscreen

import (
	"context"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

type catalog[T any] struct {
	names   []string
	entries map[string]*T
}

func (c *catalog[T]) get(name string) *T {
	if c.entries == nil {
		c.entries = make(map[string]*T)
	}
	if c.entries[name] == nil {
		c.names = append(c.names, name)
		c.entries[name] = new(T)
	}
	return c.entries[name]
}

type row struct {
	config.Statement
	scope, owner, vrf string
}
type parser struct {
	builder      *config.Builder
	rows         []row
	addresses    map[fm.ID]fm.AddressRef
	services     map[string]fm.ServiceRef
	policyNAT    map[fm.ID]policyNAT
	intraBlocked map[fm.ID]bool
}

type Parser struct{ Limits config.Limits }

func (native Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor, metadata.ParserVersion = "netscreen", "screenos-go-4"
	content, err := config.NewContent(ctx, source, native.Limits)
	if err != nil {
		return nil, err
	}
	statements, err := config.Statements(ctx, content)
	if err != nil {
		return nil, err
	}
	p := &parser{rows: scopeRows(statements), policyNAT: make(map[fm.ID]policyNAT), intraBlocked: make(map[fm.ID]bool)}
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
	if err := s.Phase(ctx, "schedules", p.schedules); err != nil {
		return nil, err
	}
	if err := s.Phase(ctx, "interface-nat", p.interfaceNAT); err != nil {
		return nil, err
	}
	if err := s.Phase(ctx, "policies", p.policies); err != nil {
		return nil, err
	}
	if err := s.Phase(ctx, "policy-nat", p.embeddedNAT); err != nil {
		return nil, err
	}
	return s.Seal()
}
