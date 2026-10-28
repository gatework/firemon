// Package fortinet parses FortiOS configuration through scoped, ordered stages.
package fortinet

import (
	"context"
	"fmt"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

type parser struct {
	vdom             string
	sections         map[string][]*config.Block
	data             fm.Data
	interfaces       map[fm.ID]fm.InterfaceRecord
	zones            map[fm.ID]fm.ZoneRecord
	intraAllow       []fm.ID
	addresses        map[string]fm.AddressRef
	services         map[string]fm.ServiceRef
	sourcePorts      flow.Interval
	poolModes        map[fm.ID]fm.TranslationMode
	interfaceDomains map[*config.Block]string
}

// Parse selects the root VDOM. ParseVDOM selects another domain explicitly.
func Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	return ParseVDOM(ctx, source, metadata, "root")
}

// ParseVDOM retains the complete source but only interprets the selected domain.
// A capture without a config vdom wrapper is assumed to be from this domain.
func ParseVDOM(ctx context.Context, source config.Source, metadata fm.Metadata, vdom string) (*fm.Firewall, error) {
	if strings.TrimSpace(vdom) == "" {
		return nil, fmt.Errorf("%w: VDOM is required", config.ErrSource)
	}
	metadata.Vendor, metadata.ParserVersion, metadata.Context = "fortinet", "fortios-go-1", vdom
	cursor, err := config.NewCursor(source, config.Limits{})
	if err != nil {
		return nil, err
	}
	var syntaxErr error
	doc, err := config.Blocks(ctx, cursor, func(st config.Statement, path []string) (config.Boundary, string) {
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
		return nil, err
	}
	if syntaxErr != nil {
		return nil, syntaxErr
	}
	if len(doc.Diagnostics) > 0 {
		return nil, fmt.Errorf("%w: unclosed native configuration block", config.ErrSource)
	}
	p := &parser{vdom: vdom, sections: make(map[string][]*config.Block), interfaces: make(map[fm.ID]fm.InterfaceRecord), zones: make(map[fm.ID]fm.ZoneRecord), addresses: make(map[string]fm.AddressRef), services: make(map[string]fm.ServiceRef), sourcePorts: flow.Interval{Low: 1, High: 65535}, poolModes: make(map[fm.ID]fm.TranslationMode)}
	session := config.NewSession(cursor, metadata)
	stages := []config.Stage{
		{Name: "context", Run: func(ctx context.Context, s *config.Session) error { return p.selectContext(ctx, s, doc) }},
		{Name: "settings", Requires: []string{"context"}, Run: p.settings},
		{Name: "interfaces-zones", Requires: []string{"settings"}, Run: p.network},
		{Name: "routes", Requires: []string{"interfaces-zones"}, Run: p.routes},
		{Name: "objects", Requires: []string{"routes"}, Run: p.objects},
		{Name: "vip-pools", Requires: []string{"objects"}, Run: p.natObjects},
		{Name: "policies", Requires: []string{"vip-pools"}, Run: p.policies},
		{Name: "evidence", Requires: []string{"policies"}, Run: func(ctx context.Context, s *config.Session) error {
			tx := s.Cursor.Begin()
			defer tx.Rollback()
			evidence := s.Cursor.Evidence()
			for _, line := range s.Cursor.Lines() {
				if err := ctx.Err(); err != nil {
					return err
				}
				raw := strings.TrimSpace(line.Raw)
				if evidence[line.Number-1].State == fm.Pending && (raw == "" || strings.HasPrefix(raw, "#")) {
					tx.Ignore("blank line or comment", line.Number)
				}
			}
			return s.Commit(tx)
		}},
	}
	if err := session.Run(ctx, stages); err != nil {
		return nil, err
	}
	return fm.Seal(session.Data())
}

func (p *parser) commit(s *config.Session, tx *config.Transaction, d fm.Data) error {
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	p.data = s.Data()
	return nil
}
func borders(tx *config.Transaction, b *config.Block) {
	tx.Parse(b.Header.Lines()...)
	tx.Parse(b.End.Lines()...)
}
func ignoreBlock(tx *config.Transaction, b *config.Block, reason string) {
	for n := b.Header.Span.First; n <= b.End.Span.Last; n++ {
		tx.Ignore(reason, n)
	}
}
func (p *parser) selectContext(ctx context.Context, s *config.Session, doc config.Document) error {
	tx := s.Cursor.Begin()
	defer tx.Rollback()
	supported := []string{"system global", "system settings", "system interface", "system zone", "router static", "firewall address", "firewall addrgrp", "firewall service custom", "firewall service group", "firewall vip", "firewall vipgrp", "firewall ippool", "firewall policy"}
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

type fields struct {
	block  *config.Block
	tx     *config.Transaction
	object *fm.Object
	values map[string]config.Statement
	used   map[string]bool
}

func readFields(tx *config.Transaction, b *config.Block, o *fm.Object) *fields {
	f := &fields{block: b, tx: tx, object: o, values: make(map[string]config.Statement), used: make(map[string]bool)}
	o.Spans = append(o.Spans, fm.Span{First: b.Header.Span.First, Last: b.End.Span.Last})
	borders(tx, b)
	for _, r := range b.Members {
		w := r.Words
		if len(w) == 0 || strings.HasPrefix(w[0], "#") {
			continue
		}
		if len(w) < 3 || w[0] != "set" {
			o.Unsupported = append(o.Unsupported, "unsupported object command")
			continue
		}
		if _, exists := f.values[w[1]]; exists {
			o.Unsupported = append(o.Unsupported, "repeated setting "+w[1])
			continue
		}
		f.values[w[1]] = r
	}
	if len(b.Children) > 0 {
		o.Unsupported = append(o.Unsupported, "unsupported nested object block")
	}
	return f
}
func (f *fields) list(key string) []string {
	r, ok := f.values[key]
	if !ok {
		return nil
	}
	if !f.used[key] {
		f.tx.Parse(r.Lines()...)
		f.used[key] = true
	}
	return slices.Clone(r.Words[2:])
}
func (f *fields) one(key, def string) string {
	if _, ok := f.values[key]; !ok {
		return def
	}
	v := f.list(key)
	if len(v) != 1 {
		f.invalid(key)
		return def
	}
	return v[0]
}
func (f *fields) invalid(key string) {
	f.object.Unsupported = append(f.object.Unsupported, "unsupported "+key)
}
func (f *fields) choice(key, def string, allowed ...string) string {
	value := f.one(key, def)
	if !slices.Contains(allowed, value) {
		f.invalid(key)
	}
	return value
}
func (f *fields) ignore(keys ...string) {
	for _, key := range keys {
		if r, ok := f.values[key]; ok && !f.used[key] {
			f.tx.Ignore("administrative object metadata", r.Lines()...)
			f.used[key] = true
		}
	}
}
func (f *fields) finish() {
	for _, r := range f.block.Members {
		if len(r.Words) >= 3 && r.Words[0] == "set" && !f.used[r.Words[1]] {
			f.invalid(r.Words[1])
		}
	}
}
func object(id, name, scope string) fm.Object {
	return fm.Object{ID: fm.ID(id), Name: name, Scope: scope}
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
