package paloalto

import (
	"context"
	"fmt"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

type xmlInput struct {
	document config.XMLDocument
	allowed  map[*config.XMLNode]bool
	empty    map[*config.XMLNode]bool
}

// xmlStatements reads native paths directly, without an intermediate generated
// set document. Every semantic row points to claims in the original XML cursor.
func xmlStatements(ctx context.Context, source config.Source, limits config.Limits) (*xmlInput, []config.Statement, error) {
	doc, err := config.XML(ctx, source, limits)
	if err != nil {
		return nil, nil, err
	}
	x := &xmlInput{document: doc, allowed: make(map[*config.XMLNode]bool), empty: make(map[*config.XMLNode]bool)}
	root := doc.Root
	if root.Name.Space != "" {
		return nil, nil, fmt.Errorf("%w: unsupported PAN XML namespace", config.ErrSource)
	}
	if root.Name.Local == "response" {
		if attribute(root, "status") != "success" || !attributes(root, "status", "code") || len(root.Children) != 1 || root.Children[0].Name.Local != "result" {
			return nil, nil, fmt.Errorf("%w: PAN response did not contain one successful result", config.ErrSource)
		}
		x.allowed[root] = true
		root = root.Children[0]
		if !attributes(root) || len(root.Children) != 1 || root.Children[0].Name.Local != "config" {
			return nil, nil, fmt.Errorf("%w: PAN result did not contain running config", config.ErrSource)
		}
		x.allowed[root] = true
		root = root.Children[0]
	}
	if root.Name.Local != "config" || !attributes(root, "version", "detail-version") {
		return nil, nil, fmt.Errorf("%w: unsupported PAN XML root", config.ErrSource)
	}
	x.allowed[root] = true
	x.empty[root] = true
	var rows []config.Statement
	var walk func(*config.XMLNode, []string) error
	walk = func(n *config.XMLNode, path []string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := n.Name.Local
		allowed := attributes(n)
		switch name {
		case "entry":
			if attribute(n, "name") == "" {
				return fmt.Errorf("%w: PAN XML entry has no name", config.ErrSource)
			}
			allowed = attributes(n, "name")
			if slices.Equal(path, []string{"vsys", "vsys1", "rulebase", "security", "rules"}) || slices.Equal(path, []string{"vsys", "vsys1", "rulebase", "nat", "rules"}) || slices.Equal(path, []string{"rulebase", "security", "rules"}) || slices.Equal(path, []string{"rulebase", "nat", "rules"}) {
				allowed = attributes(n, "name", "uuid")
			}
			name = attribute(n, "name")
		case "member":
			name = ""
		}
		if !allowed {
			return nil
		} // Unknown attributes leave the whole native subtree pending.
		x.allowed[n] = true
		next := slices.Clone(path)
		if name != "" {
			next = append(next, name)
		}
		if n.Name.Local == "devices" && len(path) == 0 {
			if len(n.Children) != 1 || n.Children[0].Name.Local != "entry" {
				return fmt.Errorf("%w: PAN device container is ambiguous", config.ErrSource)
			}
		}
		if len(next) == 2 && next[0] == "devices" && n.Name.Local == "entry" {
			next = nil
		}
		if len(n.Children) == 0 {
			if strings.TrimSpace(n.Text) == "" && emptyContainer(next) {
				x.empty[n] = true
				return nil
			}
			words := append([]string{"set"}, next...)
			if text := strings.TrimSpace(n.Text); text != "" {
				words = append(words, text)
			}
			rows = append(rows, config.Statement{Span: n.Span, Words: words, Raw: source.Text[n.Span.StartByte:n.Span.EndByte], Claims: slices.Clone(n.Claims)})
			return nil
		}
		for _, child := range n.Children {
			if err := walk(child, next); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range root.Children {
		if err := walk(child, nil); err != nil {
			return nil, nil, err
		}
	}
	return x, rows, nil
}
func attribute(n *config.XMLNode, key string) string {
	for _, a := range n.Attributes {
		if a.Name.Space == "" && a.Name.Local == key {
			return a.Value
		}
	}
	return ""
}
func attributes(n *config.XMLNode, allowed ...string) bool {
	if n.Name.Space != "" {
		return false
	}
	seen := make(map[string]bool)
	for _, a := range n.Attributes {
		if a.Name.Space != "" || seen[a.Name.Local] || !slices.Contains(allowed, a.Name.Local) {
			return false
		}
		seen[a.Name.Local] = true
	}
	return true
}
func emptyContainer(path []string) bool {
	if len(path) > 0 && path[0] == "shared" {
		path = path[1:]
	}
	if len(path) > 1 && path[0] == "vsys" && path[1] == "vsys1" {
		path = path[2:]
	}
	switch strings.Join(path, "/") {
	case "", "address", "address-group", "service", "service-group", "schedule", "zone", "network", "network/interface", "network/interface/ethernet", "network/virtual-router", "vsys", "rulebase", "rulebase/security", "rulebase/security/rules", "rulebase/nat", "rulebase/nat/rules", "rulebase/default-security-rules", "rulebase/default-security-rules/rules":
		return true
	}
	return false
}

// finish claims a structural container only after all its descendants have been
// consumed by targeted semantic stages. An unknown child keeps its ancestors pending.
func (x *xmlInput) finish(ctx context.Context, s *config.Session) error {
	states := s.Cursor.Evidence()
	tx := s.Cursor.Begin()
	tx.Ignore("XML declaration, comment or outer whitespace", x.document.Decorations...)
	var visit func(*config.XMLNode) (bool, error)
	visit = func(n *config.XMLNode) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if !x.allowed[n] {
			return false, nil
		}
		all := true
		for _, child := range n.Children {
			done, err := visit(child)
			if err != nil {
				return false, err
			}
			all = all && done
		}
		if len(n.Children) == 0 && !x.empty[n] {
			for _, claim := range n.Claims {
				if states[claim-1].State == fm.Pending {
					return false, nil
				}
			}
			return true, nil
		}
		if all {
			for _, claim := range n.Claims {
				if states[claim-1].State == fm.Pending {
					tx.Parse(claim)
				}
			}
		}
		return all, nil
	}
	if _, err := visit(x.document.Root); err != nil {
		tx.Rollback()
		return err
	}
	return s.Commit(tx)
}
