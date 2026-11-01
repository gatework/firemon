package asa

import (
	"context"

	"slices"

	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func object(b block) fm.Object {
	return fm.Object{ID: fm.ID(b.name), Name: b.name, Spans: []fm.Span{b.header.Span}}
}

func (p *parser) scan(ctx context.Context, statements []config.Statement) error {
	owner := -1
	for _, line := range statements {
		if err := ctx.Err(); err != nil {
			return err
		}
		w := line.Words
		if len(w) == 0 || strings.HasPrefix(w[0], "!") {
			p.lines = append(p.lines, line)
			owner = -1
			continue
		}
		if w[0] == "interface" && len(w) == 2 {
			p.blocks = append(p.blocks, block{header: line, kind: "interface", name: w[1]})
			owner = len(p.blocks) - 1
			continue
		}
		if (w[0] == "object" || w[0] == "object-group") && len(w) >= 3 {
			b := block{header: line, kind: w[0] + "/" + w[1], name: w[2]}
			if len(w) > 3 {
				b.protocol = w[3]
			}
			p.blocks = append(p.blocks, b)
			owner = len(p.blocks) - 1
			continue
		}
		top := slices.Contains([]string{"access-list", "access-group", "route", "global", "static", "nat"}, w[0])
		if w[0] == "nat" && owner >= 0 && p.blocks[owner].kind == "object/network" && len(w) > 2 && (w[2] == "static" || w[2] == "dynamic") {
			top = false
		}
		if top {
			owner = -1
			p.lines = append(p.lines, line)
		} else if owner >= 0 {
			p.blocks[owner].members = append(p.blocks[owner].members, line)
		} else {
			p.lines = append(p.lines, line)
		}
	}
	return ctx.Err()
}
