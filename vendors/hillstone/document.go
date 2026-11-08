package hillstone

import (
	"context"
	"fmt"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

// document retains native scopes and source order without consuming evidence.
type document struct {
	tree  config.Document
	nodes []node
	lines []statement
}

type node struct {
	block           *config.Block
	scope, from, to string
}

type statement struct {
	line  config.Statement
	scope string
}

func readDocument(ctx context.Context, content *config.Content) (*document, error) {
	tree, err := config.Blocks(ctx, content, (&scanner{lines: content.Lines()}).classify)
	if err != nil {
		return nil, err
	}
	doc := &document{tree: tree}
	doc.collect(tree.Roots, "", "", "")
	for _, line := range tree.Lines {
		doc.lines = append(doc.lines, statement{line: line})
	}
	return doc, nil
}

// A definition retains all reopenings of one native object in source order.
type definition struct {
	kind   string
	id     fm.ID
	scope  string
	blocks []*config.Block
}

func (doc *document) definitions(ctx context.Context, kinds ...string) ([]definition, error) {
	type key struct {
		kind string
		id   fm.ID
	}
	definitions := []definition{}
	indexes := make(map[key]int)
	for _, n := range doc.nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !slices.Contains(kinds, n.block.Kind) {
			continue
		}
		w := n.block.Header.Words
		if !definitionHeader(w) {
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
		if len(b.Children) > 0 {
			o.Unsupported = append(o.Unsupported, "nested object configuration")
		}
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

func (doc *document) collect(blocks []*config.Block, scope, from, to string) {
	for _, b := range blocks {
		w := b.Header.Words
		switch b.Kind {
		case "vrf":
			if contextHeader(b) {
				doc.collect(b.Children, w[2], from, to)
				for _, line := range b.Members {
					doc.lines = append(doc.lines, statement{line: line, scope: w[2]})
				}
			}
		case "policy":
			if contextHeader(b) {
				doc.collect(b.Children, scope, w[2], w[4])
			}
		case "policy-global":
			if contextHeader(b) {
				doc.collect(b.Children, scope, "any", "any")
			}
		default:
			doc.nodes = append(doc.nodes, node{block: b, scope: scope, from: from, to: to})
		}
	}
}
func (doc *document) structure(ctx context.Context, s *config.Builder) error {
	tx := s.Begin()
	tx.Emit(fm.Data{Diagnostics: doc.tree.Diagnostics})
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
	mark(doc.tree.Roots)
	for _, row := range doc.lines {
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
	o := fm.Object{ID: fm.ID(id), Name: id, Scope: n.scope, Spans: []fm.Span{n.block.Header.Span}}
	if len(n.block.Children) > 0 {
		o.Unsupported = append(o.Unsupported, "nested object configuration")
	}
	return o
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
