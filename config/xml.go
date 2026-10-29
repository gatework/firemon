package config

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

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
	Cursor      *Cursor
	Decorations []int // whitespace outside the root, comments and declaration
}

// XML performs only bounded native structure scanning. DTDs/entities, mixed
// content, extra roots and namespaces unsupported by a vendor cannot become
// command text. No external entity resolver or network access is installed.
func XML(ctx context.Context, source Source, limits Limits) (XMLDocument, error) {
	limits = limits.defaults()
	if err := ctx.Err(); err != nil {
		return XMLDocument{}, err
	}
	if len(source.Text) > limits.MaxBytes || !utf8.ValidString(source.Text) {
		return XMLDocument{}, ErrSource
	}
	decoder := xml.NewDecoder(strings.NewReader(source.Text))
	var document XMLDocument
	var stack []*XMLNode
	var spans []fm.Span
	line := 1
	for {
		if err := ctx.Err(); err != nil {
			return XMLDocument{}, err
		}
		start := int(decoder.InputOffset())
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return XMLDocument{}, fmt.Errorf("%w: malformed XML: %w", ErrSource, err)
		}
		end := int(decoder.InputOffset())
		span := fm.Span{First: line, Last: line, StartByte: start, EndByte: end}
		for i := start; i < end; i++ {
			if source.Text[i] == '\n' {
				line++
			} else if source.Text[i] == '\r' && (i+1 == len(source.Text) || source.Text[i+1] != '\n') {
				line++
			}
			if i < end-1 {
				span.Last = line
			}
		}
		claim := 0
		if end > start {
			if len(spans) >= limits.MaxLines || line > limits.MaxLines+1 {
				return XMLDocument{}, fmt.Errorf("%w: XML token/line budget", ErrSource)
			}
			spans = append(spans, span)
			claim = len(spans)
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
	cursor, err := NewFragmentCursor(source, spans, limits)
	if err != nil {
		return XMLDocument{}, err
	}
	document.Cursor = cursor
	return document, nil
}
