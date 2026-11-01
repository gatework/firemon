package hillstone

import (
	"context"
	"fmt"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

// A definition retains all reopenings of one native object in source order.
type definition struct {
	kind   string
	id     fm.ID
	scope  string
	blocks []*config.Block
}

func (p *parser) definitions(ctx context.Context, kinds ...string) ([]definition, error) {
	type key struct {
		kind string
		id   fm.ID
	}
	definitions := []definition{}
	indexes := make(map[key]int)
	for _, n := range p.nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !slices.Contains(kinds, n.block.Kind) {
			continue
		}
		w := n.block.Header.Words
		if !namedHeader(w) {
			continue
		}
		k := key{kind: n.block.Kind, id: fm.ID(w[1])}
		if index, exists := indexes[k]; exists {
			d := &definitions[index]
			if d.scope != n.scope {
				return nil, fmt.Errorf(
					"%w: %s %q reopened in scopes %q and %q",
					config.ErrSource, d.kind, d.id, d.scope, n.scope,
				)
			}
			d.blocks = append(d.blocks, n.block)
			continue
		}
		indexes[k] = len(definitions)
		definitions = append(definitions, definition{
			kind: k.kind, id: k.id, scope: n.scope, blocks: []*config.Block{n.block},
		})
	}
	return definitions, ctx.Err()
}

func (d definition) object() fm.Object {
	return fm.Object{ID: d.id, Name: string(d.id), Scope: d.scope}
}

func (d definition) walk(
	ctx context.Context,
	tx *config.Transaction,
	o *fm.Object,
	member func([]string) bool,
) error {
	for _, b := range d.blocks {
		if err := ctx.Err(); err != nil {
			return err
		}
		tx.Parse(b.Header.Lines()...)
		o.Spans = append(o.Spans, b.Header.Span)
		for _, line := range b.Members {
			if err := ctx.Err(); err != nil {
				return err
			}
			consume(tx, line, member(line.Words), o)
		}
		if b.Complete {
			tx.Parse(b.End.Lines()...)
		}
	}
	return ctx.Err()
}

func classify(s config.Statement, path []string) (config.Boundary, string) {
	w := s.Words
	if len(w) == 0 {
		return config.Member, ""
	}
	if len(w) == 1 && w[0] == "exit" {
		return config.CloseBlock, ""
	}
	owner := ""
	if len(path) > 0 {
		owner = path[len(path)-1]
	}
	if owner == "outside" || owner == "unknown" {
		return config.Member, ""
	}
	if owner != "" && owner != "vrf" && owner != "policy" && owner != "policy-global" {
		if owner == "pbr-policy" && w[0] == "match" {
			return config.OpenBlock, "pbr-match"
		}
		return config.Member, ""
	}
	switch w[0] {
	case "zone", "interface", "address", "service", "servgroup", "schedule", "rule", "natpool", "pbr-policy":
		return config.OpenBlock, w[0]
	case "policy-global":
		return config.OpenBlock, "policy-global"
	case "policy":
		if len(w) > 1 && w[1] == "from" {
			return config.OpenBlock, "policy"
		}
	case "ip":
		if len(w) > 1 && w[1] == "vrouter" {
			return config.OpenBlock, "vrf"
		}
	case "admin", "aaa-server", "role", "track", "interface-group", "webauth", "vswitch":
		return config.OpenBlock, "outside"
	}
	if strings.HasSuffix(w[0], "-profile") {
		return config.OpenBlock, "outside"
	}
	return config.Member, ""
}

func namedHeader(w []string) bool {
	return len(w) == 2 && strings.TrimSpace(w[1]) != ""
}

// Structural scanning keeps malformed wrappers scoped. Interpretation and
// source claims must both accept the complete native header before entering it.
func contextHeader(b *config.Block) bool {
	w := b.Header.Words
	switch b.Kind {
	case "vrf":
		return len(w) == 3 && strings.TrimSpace(w[2]) != ""
	case "policy":
		return len(w) == 5 && w[1] == "from" && w[3] == "to" && strings.TrimSpace(w[2]) != "" && strings.TrimSpace(w[4]) != ""
	case "policy-global":
		return len(w) == 1
	}
	return false
}

func ruleHeader(w []string) bool {
	if len(w) == 3 && w[1] == "id" {
		return strings.TrimSpace(w[2]) != ""
	}
	return namedHeader(w) && w[1] != "id"
}

func (p *parser) collect(blocks []*config.Block, scope, from, to string) {
	for _, b := range blocks {
		w := b.Header.Words
		switch b.Kind {
		case "vrf":
			if contextHeader(b) {
				p.collect(b.Children, w[2], from, to)
				for _, line := range b.Members {
					p.lines = append(p.lines, statement{line, w[2]})
				}
			}
		case "policy":
			if contextHeader(b) {
				p.collect(b.Children, scope, w[2], w[4])
			}
		case "policy-global":
			if contextHeader(b) {
				p.collect(b.Children, scope, "any", "any")
			}
		default:
			p.nodes = append(p.nodes, node{b, scope, from, to})
		}
	}
}
func (p *parser) structure(ctx context.Context, s *config.Builder) error {
	tx := s.Begin()
	tx.Emit(fm.Data{Diagnostics: p.document.Diagnostics})
	var mark func([]*config.Block)
	mark = func(blocks []*config.Block) {
		for _, b := range blocks {
			switch b.Kind {
			case "vrf", "policy", "policy-global":
				if !contextHeader(b) {
					continue
				}
				tx.Parse(b.Header.Lines()...)
				if b.Complete {
					tx.Parse(b.End.Lines()...)
				}
				mark(b.Children)
			case "outside":
				tx.Ignore("native management block outside firewall domain", b.Header.Lines()...)
				for _, l := range b.Members {
					tx.Ignore("native management block outside firewall domain", l.Lines()...)
				}
				if b.Complete {
					tx.Ignore("native management block boundary", b.End.Lines()...)
				}
			}
		}
	}
	mark(p.document.Roots)
	for _, row := range p.lines {
		w := row.line.Words
		if len(w) == 0 || strings.HasPrefix(w[0], "#") || strings.HasPrefix(w[0], "!") || w[0] == "hostname" {
			tx.Ignore("comment or device display name", row.line.Lines()...)
		}
	}
	return s.Commit(tx)
}
func object(n node) fm.Object {
	w := n.block.Header.Words
	id := ""
	if len(w) > 1 {
		id = w[1]
	}
	if w[0] == "rule" && len(w) > 2 && w[1] == "id" {
		id = w[2]
	}
	return fm.Object{ID: fm.ID(id), Name: id, Scope: n.scope, Spans: []fm.Span{n.block.Header.Span}}
}
func begin(s *config.Builder, b *config.Block) *config.Transaction {
	tx := s.Begin()
	tx.Parse(b.Header.Lines()...)
	if b.Complete {
		tx.Parse(b.End.Lines()...)
	}
	return tx
}
func consume(tx *config.Transaction, line config.Statement, ok bool, o *fm.Object) {
	if ok {
		tx.Parse(line.Lines()...)
		o.Spans = append(o.Spans, line.Span)
	} else {
		o.Unsupported = append(o.Unsupported, strings.TrimSpace(line.Raw))
	}
}
func ancillary(w []string) bool { return len(w) == 0 || w[0] == "description" }
