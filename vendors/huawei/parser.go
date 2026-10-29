// Package huawei parses scoped USG configuration through dependency-ordered stages.
package huawei

import (
	"context"
	"fmt"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/vendors/internal/draft"
)

type parser struct {
	blocks    []*config.Block
	lines     []config.Statement
	data      fm.Data
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
	metadata.Vendor, metadata.ParserVersion = "huawei", "huawei-go-1"
	cursor, err := config.NewCursor(source, native.Limits)
	if err != nil {
		return nil, err
	}
	rows, err := config.Statements(ctx, cursor)
	if err != nil {
		return nil, err
	}
	p := &parser{addresses: make(map[string]fm.AddressRef), services: make(map[string]fm.ServiceRef)}
	p.data.Metadata = metadata
	var block *config.Block
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		w := row.Words
		if len(w) == 1 && w[0] == "#" && indent(row) == 0 {
			if block != nil {
				block.End = row
				block.Complete = true
				block = nil
			}
			p.lines = append(p.lines, row)
			continue
		}
		if block != nil {
			block.Members = append(block.Members, row)
			continue
		}
		if len(w) == 0 {
			p.lines = append(p.lines, row)
			continue
		}
		kind := blockKind(w)
		if indent(row) != 0 {
			kind = "unknown"
		}
		if kind == "" && standalone(w) {
			p.lines = append(p.lines, row)
			continue
		}
		if kind == "" {
			kind = "unknown"
		}
		block = &config.Block{Kind: kind, Header: row}
		p.blocks = append(p.blocks, block)
	}
	if block != nil && block.Kind != "unknown" {
		return nil, fmt.Errorf("%w: missing # after line %d", config.ErrSource, block.Header.Span.First)
	}
	s, err := config.NewSession(cursor, metadata)
	if err != nil {
		return nil, err
	}
	stages := []config.Stage{
		{Name: "interfaces-zones", Run: p.network},
		{Name: "routes", Requires: []string{"interfaces-zones"}, Run: p.routes},
		{Name: "objects", Requires: []string{"routes"}, Run: p.objects},
		{Name: "policies", Requires: []string{"objects"}, Run: p.policies},
		{Name: "nat", Requires: []string{"policies"}, Run: p.nat},
		{Name: "evidence", Requires: []string{"nat"}, Run: p.evidence},
	}
	if err := s.Run(ctx, stages); err != nil {
		return nil, err
	}
	return fm.Seal(s.Data())
}
func blockKind(w []string) string {
	switch {
	case w[0] == "interface":
		return "interface"
	case has(w, "firewall", "zone"):
		return "zone"
	case has(w, "ip", "address-set"):
		return "address"
	case has(w, "ip", "service-set"):
		return "service"
	case w[0] == "security-policy":
		return "security-policy"
	case w[0] == "nat-policy":
		return "nat-policy"
	case has(w, "nat", "address-group"):
		return "source-pool"
	case has(w, "destination-nat", "address-group"):
		return "destination-pool"
	case w[0] == "time-range":
		return "schedule"
	}
	return ""
}
func standalone(w []string) bool {
	return has(w, "ip", "route-static") || has(w, "nat", "server") || w[0] == "sysname" || w[0] == "return" || w[0] == "!Software" || w[0] == "!Last"
}
func has(w []string, prefix ...string) bool {
	if len(w) < len(prefix) {
		return false
	}
	for i, v := range prefix {
		if w[i] != v {
			return false
		}
	}
	return true
}
func indent(row config.Statement) int {
	n := 0
	for _, r := range row.Raw {
		if r != ' ' && r != '\t' {
			break
		}
		n++
	}
	return n
}
func object(name string) fm.Object { return fm.Object{ID: fm.ID(name), Name: name} }
func (p *parser) commit(s *config.Session, tx *config.Transaction, d fm.Data) error {
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	draft.Append(&p.data, d)
	return nil
}
func claim(tx *config.Transaction, o *fm.Object, row config.Statement, ok bool) {
	if ok {
		tx.Parse(row.Lines()...)
		o.Spans = append(o.Spans, row.Span)
	} else {
		o.Unsupported = append(o.Unsupported, strings.TrimSpace(row.Raw))
	}
}

type namedBlocks struct {
	name, kind string
	blocks     []*config.Block
}

func (p *parser) grouped(kind string, header func([]string) (string, string, error)) ([]namedBlocks, error) {
	var out []namedBlocks
	index := make(map[string]int)
	for _, b := range p.blocks {
		if b.Kind != kind {
			continue
		}
		name, typ, err := header(b.Header.Words)
		if err != nil {
			return nil, fmt.Errorf("%w at line %d: %v", config.ErrSource, b.Header.Span.First, err)
		}
		if i, ok := index[name]; ok {
			if typ != "" && typ != out[i].kind {
				return nil, fmt.Errorf("%w: %s changes type", config.ErrSource, name)
			}
			out[i].blocks = append(out[i].blocks, b)
		} else {
			if typ == "" {
				return nil, fmt.Errorf("%w: %s reopened before declaration", config.ErrSource, name)
			}
			index[name] = len(out)
			out = append(out, namedBlocks{name: name, kind: typ, blocks: []*config.Block{b}})
		}
	}
	return out, nil
}
func walk(ctx context.Context, tx *config.Transaction, o *fm.Object, g namedBlocks, visit func(config.Statement) bool) error {
	for _, b := range g.blocks {
		if err := ctx.Err(); err != nil {
			return err
		}
		claim(tx, o, b.Header, true)
		for _, row := range b.Members {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(row.Words) == 0 {
				continue
			}
			claim(tx, o, row, indent(row) == 1 && visit(row))
		}
	}
	return nil
}
func (p *parser) evidence(ctx context.Context, s *config.Session) error {
	tx := s.Cursor().Begin()
	defer tx.Rollback()
	for _, row := range p.lines {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := row.Words
		if len(w) > 0 && w[0] == "#" {
			tx.Ignore("blank line or native section boundary", row.Lines()...)
		}
		if len(w) > 0 && (w[0] == "sysname" || w[0] == "return" || w[0] == "!Software" || w[0] == "!Last") {
			tx.Ignore("capture metadata or system-view boundary", row.Lines()...)
		}
	}
	for _, line := range s.Cursor().Lines() {
		if strings.TrimSpace(line.Raw) == "" {
			tx.Ignore("blank line", line.Number)
		}
	}
	return s.Commit(tx)
}
