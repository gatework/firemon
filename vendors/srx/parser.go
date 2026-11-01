// Package srx parses Junos display-set configuration through targeted stages.
package srx

import (
	"context"

	"net/netip"

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

type parser struct {
	builder   *config.Builder
	rows      []config.Statement
	books     map[string][]string // attached books by zone
	addresses map[fm.ID]fm.AddressRef
}

type Parser struct{ Limits config.Limits }

func Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	return (Parser{}).Parse(ctx, source, metadata)
}

func (native Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor, metadata.ParserVersion = "srx", "srx-go-2"
	content, err := config.NewContent(ctx, source, native.Limits)
	if err != nil {
		return nil, err
	}
	rows, err := config.Statements(ctx, content)
	if err != nil {
		return nil, err
	}
	p := &parser{rows: rows, books: make(map[string][]string)}
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
	return s.Seal()
}

type routeDraft struct {
	object      fm.Object
	destination netip.Prefix
	hops        []string
	metric      uint32
}
