// Package fortinet parses FortiOS configuration through scoped, ordered stages.
package fortinet

import (
	"context"
	"fmt"

	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
	"github.com/gatework/firemon/flow"
)

type parser struct {
	builder          *config.Builder
	vdom             string
	sections         map[string][]*config.Block
	intraAllow       []fm.ID
	addresses        map[string]fm.AddressRef
	services         map[string]fm.ServiceRef
	sourcePorts      flow.Interval
	poolModes        map[fm.ID]fm.TranslationMode
	interfaceDomains map[*config.Block]string
}

// Parser retains the capture and interprets Metadata.Context, defaulting to
// root. Captures without a config vdom wrapper belong to that selected domain.
type Parser struct{ Limits config.Limits }

func (native Parser) Parse(ctx context.Context, source config.Source, metadata fm.Metadata) (*fm.Firewall, error) {
	vdom := metadata.Context
	if vdom == "" {
		vdom = "root"
	}
	if strings.TrimSpace(vdom) == "" {
		return nil, fmt.Errorf("%w: VDOM is required", config.ErrSource)
	}
	metadata.Vendor, metadata.ParserVersion, metadata.Context = "fortinet", "fortios-go-4", vdom
	content, err := config.NewContent(ctx, source, native.Limits)
	if err != nil {
		return nil, err
	}
	doc, err := scan(ctx, content)
	if err != nil {
		return nil, err
	}
	p := &parser{vdom: vdom, sections: make(map[string][]*config.Block), addresses: make(map[string]fm.AddressRef), services: make(map[string]fm.ServiceRef), sourcePorts: flow.Interval{Low: 1, High: 65535}, poolModes: make(map[fm.ID]fm.TranslationMode)}
	builder, err := config.NewBuilder(content, metadata)
	if err != nil {
		return nil, err
	}
	p.builder = builder
	if err := builder.Phase(ctx, "context", func(ctx context.Context, s *config.Builder) error { return p.selectContext(ctx, s, doc) }); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "settings", p.settings); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "interfaces-zones", p.network); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "routes", p.routes); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "objects", p.objects); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "schedules", p.schedules); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "vip-pools", p.natObjects); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "policies", p.policies); err != nil {
		return nil, err
	}
	if err := builder.Phase(ctx, "evidence", func(ctx context.Context, s *config.Builder) error {
		tx := s.Begin()
		defer tx.Rollback()
		evidence := s.Content().Evidence()
		for _, line := range s.Content().Lines() {
			if err := ctx.Err(); err != nil {
				return err
			}
			raw := strings.TrimSpace(line.Raw)
			if evidence[line.Number-1].State == fm.Pending && (raw == "" || strings.HasPrefix(raw, "#")) {
				tx.Ignore("blank line or comment", line.Number)
			}
		}
		return s.Commit(tx)
	}); err != nil {
		return nil, err
	}
	return builder.Seal()
}

func (p *parser) commit(s *config.Builder, tx *config.Transaction, d fm.Data) error {
	tx.Emit(d)
	if err := s.Commit(tx); err != nil {
		return err
	}
	return nil
}

type fields struct {
	block  *config.Block
	tx     *config.Transaction
	object *fm.Object
	values map[string]config.Statement
	used   map[string]bool
}

func object(id, name, scope string) fm.Object {
	return fm.Object{ID: fm.ID(id), Name: name, Scope: scope}
}
