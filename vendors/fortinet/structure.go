package fortinet

import (
	"context"
	"fmt"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func borders(tx *config.Transaction, b *config.Block) {
	tx.Parse(b.Header.Lines()...)
	tx.Parse(b.End.Lines()...)
}
func ignoreBlock(tx *config.Transaction, b *config.Block, reason string) {
	for n := b.Header.Span.First; n <= b.End.Span.Last; n++ {
		tx.Ignore(reason, n)
	}
}
func (p *parser) selectContext(ctx context.Context, s *config.Builder, doc config.Document) error {
	tx := s.Begin()
	defer tx.Rollback()
	supported := []string{"system global", "system settings", "system interface", "system zone", "router static", "firewall address", "firewall addrgrp", "firewall service custom", "firewall service group", "firewall vip", "firewall vipgrp", "firewall ippool", "firewall policy", "firewall schedule onetime", "firewall schedule recurring"}
	p.interfaceDomains = make(map[*config.Block]string)
	add := func(b *config.Block, domain string) {
		key := strings.TrimPrefix(b.Kind, "config ")
		if slices.Contains(supported, key) {
			p.sections[key] = append(p.sections[key], b)
			if key == "system interface" {
				for _, entry := range b.Children {
					p.interfaceDomains[entry] = domain
				}
			}
		}
	}
	explicitVDOM := slices.ContainsFunc(doc.Roots, func(b *config.Block) bool { return b.Kind == "config vdom" })
	foundVDOM := false
	for _, b := range doc.Roots {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch b.Kind {
		case "config vdom":
			borders(tx, b)
			for _, domain := range b.Children {
				if domain.Kind != "edit" {
					continue
				}
				if domain.Header.Words[1] != p.vdom {
					ignoreBlock(tx, domain, "different selected VDOM")
					continue
				}
				borders(tx, domain)
				foundVDOM = true
				for _, section := range domain.Children {
					if section.Kind != "config system global" {
						add(section, p.vdom)
					}
				}
			}
		case "config global":
			borders(tx, b)
			for _, section := range b.Children {
				if section.Kind == "config system interface" || section.Kind == "config system global" {
					add(section, "root")
				}
			}
		default:
			if explicitVDOM {
				if b.Kind == "config system interface" || b.Kind == "config system global" {
					add(b, "root")
				}
			} else {
				add(b, p.vdom)
			}
		}
	}
	d := fm.Data{}
	if explicitVDOM && !foundVDOM {
		d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Code: "missing-vdom", Message: "selected VDOM is absent from this capture"})
	}
	return p.commit(s, tx, d)
}

func (p *parser) each(ctx context.Context, tx *config.Transaction, key string, fn func(*config.Block)) error {
	seen := make(map[string]bool)
	for _, section := range p.sections[key] {
		borders(tx, section)
		for _, b := range section.Children {
			if err := ctx.Err(); err != nil {
				return err
			}
			if b.Kind != "edit" {
				continue
			}
			name := b.Header.Words[1]
			if seen[name] {
				return fmt.Errorf("%w: duplicate %s object %q", config.ErrSource, key, name)
			}
			seen[name] = true
			fn(b)
		}
	}
	return nil
}

func scan(ctx context.Context, content *config.Content) (config.Document, error) {
	var syntaxErr error
	doc, err := config.Blocks(ctx, content, func(st config.Statement, path []string) (config.Boundary, string) {
		w := st.Words
		if len(w) == 0 {
			return config.Member, ""
		}
		switch w[0] {
		case "config":
			if len(w) >= 2 {
				return config.OpenBlock, strings.Join(w, " ")
			}
		case "edit":
			if len(w) == 2 && w[1] != "" {
				return config.OpenBlock, "edit"
			}
		case "next", "end":
			if len(w) == 1 && len(path) > 0 && ((w[0] == "next" && path[len(path)-1] == "edit") || (w[0] == "end" && strings.HasPrefix(path[len(path)-1], "config "))) {
				return config.CloseBlock, ""
			}
			syntaxErr = fmt.Errorf("%w: unexpected %s at line %d", config.ErrSource, w[0], st.Span.First)
		}
		return config.Member, ""
	})
	if err != nil {
		return config.Document{}, err
	}
	if syntaxErr != nil {
		return config.Document{}, syntaxErr
	}
	if len(doc.Diagnostics) > 0 {
		return config.Document{}, fmt.Errorf("%w: unclosed native configuration block", config.ErrSource)
	}
	return doc, nil
}
