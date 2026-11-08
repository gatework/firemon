package config

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
)

// XMLNode retains native ancestry, attributes and exact byte evidence. Claims
// cover only this node's tokens; child claims are never swallowed by a parent.
type XMLNode struct {
	Name       xml.Name
	Attributes []xml.Attr
	Text       string
	Children   []*XMLNode
	Span       fm.Span
	Claims     []int
	text       strings.Builder
}
type XMLDocument struct {
	Root        *XMLNode
	Content     *Content
	Decorations []int // whitespace outside the root, comments and declaration
}

// XML performs only bounded native structure scanning. DTDs/entities, mixed
// content, extra roots and namespaces unsupported by a vendor cannot become
// command text. No external entity resolver or network access is installed.
func XML(ctx context.Context, source Source, limits Limits) (XMLDocument, error) {
	c, err := newContent(ctx, source, limits)
	if err != nil {
		return XMLDocument{}, err
	}
	limits = c.limits
	decoder := xml.NewDecoder(strings.NewReader(source.Text))
	var document XMLDocument
	var stack []*XMLNode
	for {
		if err := ctx.Err(); err != nil {
			return XMLDocument{}, err
		}
		start := int(decoder.InputOffset())
		token, err := decoder.Token()
		if err := ctx.Err(); err != nil {
			return XMLDocument{}, err
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return XMLDocument{}, fmt.Errorf("%w: malformed XML: %w", ErrSource, err)
		}
		end := int(decoder.InputOffset())
		var span fm.Span
		claim := 0
		if end > start {
			if len(c.evidence) >= limits.MaxLines {
				return XMLDocument{}, fmt.Errorf("%w: XML token budget", ErrSource)
			}
			var ok bool
			span, ok = c.span(start, end)
			if !ok {
				return XMLDocument{}, ErrSource
			}
			c.evidence = append(c.evidence, fm.Evidence{Span: span, State: fm.Pending})
			claim = len(c.evidence)
		}
		switch value := token.(type) {
		case xml.StartElement:
			if len(stack) >= limits.MaxDepth {
				return XMLDocument{}, fmt.Errorf("%w: XML nesting budget", ErrSource)
			}
			n := &XMLNode{Name: value.Name, Attributes: slices.Clone(value.Attr), Span: span, Claims: []int{claim}}
			if len(stack) == 0 {
				if document.Root != nil {
					return XMLDocument{}, fmt.Errorf("%w: multiple XML roots", ErrSource)
				}
				document.Root = n
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return XMLDocument{}, ErrSource
			}
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if claim != 0 {
				n.Claims = append(n.Claims, claim)
				n.Span.EndByte = end
				n.Span.Last = span.Last
			}
			n.Text = n.text.String()
			n.text.Reset()
			if len(n.Children) > 0 && strings.TrimSpace(n.Text) != "" {
				return XMLDocument{}, fmt.Errorf("%w: mixed XML content", ErrSource)
			}
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(value)) != "" && !(start == 0 && string(value) == "\ufeff") {
					return XMLDocument{}, fmt.Errorf("%w: text outside XML root", ErrSource)
				}
				document.Decorations = append(document.Decorations, claim)
			} else {
				n := stack[len(stack)-1]
				n.text.Write(value)
				n.Claims = append(n.Claims, claim)
			}
		case xml.Comment:
			document.Decorations = append(document.Decorations, claim)
		case xml.ProcInst:
			if value.Target != "xml" || document.Root != nil {
				return XMLDocument{}, fmt.Errorf("%w: unsupported XML processing instruction", ErrSource)
			}
			document.Decorations = append(document.Decorations, claim)
		case xml.Directive:
			return XMLDocument{}, fmt.Errorf("%w: XML directives and entities are unsupported", ErrSource)
		}
	}
	if document.Root == nil || len(stack) != 0 {
		return XMLDocument{}, ErrSource
	}
	document.Content = c
	return document, nil
}
