// Package paloalto parses native PAN-OS configuration paths without flattening unknown conditions.
package paloalto

import (
	"context"

	"net/netip"

	"strings"
	"time"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

type row struct {
	source config.Statement
	words  []string
	shared bool
}
type parser struct {
	rows     []row
	builder  *config.Builder
	graph    *fm.Firewall
	location *time.Location
	prefixes map[fm.ID]netip.Prefix
}

type Parser struct{ Limits config.Limits }

func Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	return (Parser{}).Parse(ctx, source, metadata)
}

func (adapter Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	metadata.Vendor = "paloalto"
	metadata.ParserVersion = "paloalto-go-4"
	var c *config.Content
	var statements []config.Statement
	var native *xmlInput
	var err error
	if strings.HasPrefix(strings.TrimLeft(source.Text, " \t\r\n\ufeff"), "<") {
		native, statements, err = xmlStatements(ctx, source, adapter.Limits)
		if err != nil {
			return nil, err
		}
		c = native.document.Content
	} else {
		c, err = config.NewContent(ctx, source, adapter.Limits)
		if err != nil {
			return nil, err
		}
		statements, err = config.Statements(ctx, c)
		if err != nil {
			return nil, err
		}
	}
	builder, err := config.NewBuilder(c, metadata)
	if err != nil {
		return nil, err
	}
	p := &parser{builder: builder, prefixes: make(map[fm.ID]netip.Prefix)}
	for _, line := range statements {
		w := line.Words
		if len(w) == 0 {
			p.rows = append(p.rows, row{source: line})
			continue
		}
		if w[0] != "set" {
			continue
		}
		w = w[1:]
		shared := false
		if len(w) > 0 && w[0] == "shared" {
			shared = true
			w = w[1:]
		}
		if len(w) > 1 && w[0] == "vsys" {
			if w[1] != "vsys1" {
				continue
			}
			w = w[2:]
		}
		p.rows = append(p.rows, row{line, w, shared})
	}
	if err := p.builder.Phase(ctx, "objects", p.objects); err != nil {
		return nil, err
	}
	if err := p.builder.Phase(ctx, "network", p.network); err != nil {
		return nil, err
	}
	if err := p.builder.Phase(ctx, "rules", p.rules); err != nil {
		return nil, err
	}
	if err := p.builder.Phase(ctx, "nat", p.nat); err != nil {
		return nil, err
	}
	if native != nil {
		if err := p.builder.Phase(ctx, "xml-evidence", native.finish); err != nil {
			return nil, err
		}
	}
	return p.builder.Seal()
}
