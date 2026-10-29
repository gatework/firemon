package config

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	fm "github.com/gatework/firemon"
)

type Statement struct {
	Span  fm.Span
	Words []string
	Raw   string
	// Claims selects fragment indexes for native byte-oriented sources. Nil uses
	// the physical line range, as with line-based CLI configuration.
	Claims []int
}

// Statements lexes quotes and escapes across physical lines without claiming semantic evidence.
// A native vendor scanner decides which statements are blocks or members.
func Statements(ctx context.Context, c *Cursor) ([]Statement, error) {
	var out []Statement
	var words []string
	var word, raw strings.Builder
	quote := rune(0)
	escaped, active := false, false
	first := 1
	flush := func() {
		if active {
			words = append(words, word.String())
			word.Reset()
			active = false
		}
	}
	for _, line := range c.lines {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw.WriteString(line.Raw)
		for _, r := range line.Raw {
			if escaped {
				word.WriteRune(r)
				escaped = false
				active = true
				continue
			}
			if r == '\\' {
				escaped = true
				active = true
				continue
			}
			if quote != 0 {
				if r == quote {
					quote = 0
				} else {
					word.WriteRune(r)
				}
				active = true
				continue
			}
			if r == '"' || r == '\'' {
				quote = r
				active = true
				continue
			}
			if unicode.IsSpace(r) {
				flush()
			} else {
				word.WriteRune(r)
				active = true
			}
		}
		if quote == 0 && !escaped {
			flush()
			out = append(out, Statement{Span: fm.Span{First: first, Last: line.Number}, Words: words, Raw: raw.String()})
			words = nil
			raw.Reset()
			first = line.Number + 1
		}
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("%w: unterminated quote or escape at line %d", ErrSource, first)
	}
	return out, nil
}

type Boundary uint8

const (
	Member Boundary = iota
	OpenBlock
	CloseBlock
)

type Classifier func(Statement, []string) (Boundary, string)
type Block struct {
	Kind     string
	Header   Statement
	End      Statement
	Members  []Statement
	Children []*Block
	Complete bool
}
type Document struct {
	Roots       []*Block
	Lines       []Statement
	Diagnostics []fm.Diagnostic
}

// Blocks is a native-classifier-driven structural pass. Unknown native blocks remain scoped.
func Blocks(ctx context.Context, c *Cursor, classify Classifier) (Document, error) {
	statements, err := Statements(ctx, c)
	if err != nil {
		return Document{}, err
	}
	var d Document
	var stack []*Block
	for _, line := range statements {
		if err := ctx.Err(); err != nil {
			return Document{}, err
		}
		path := make([]string, len(stack))
		for i, b := range stack {
			path[i] = b.Kind
		}
		boundary, kind := classify(line, path)
		switch boundary {
		case OpenBlock:
			if len(stack) >= c.limits.MaxDepth {
				return Document{}, fmt.Errorf("%w: block depth exceeded", ErrSource)
			}
			b := &Block{Kind: kind, Header: line}
			if len(stack) == 0 {
				d.Roots = append(d.Roots, b)
			} else {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, b)
			}
			stack = append(stack, b)
		case CloseBlock:
			if len(stack) == 0 {
				d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Code: "unexpected-exit", Span: line.Span, Message: "block terminator without opening block"})
				d.Lines = append(d.Lines, line)
			} else {
				b := stack[len(stack)-1]
				b.Complete = true
				b.End = line
				stack = stack[:len(stack)-1]
			}
		default:
			if len(stack) == 0 {
				d.Lines = append(d.Lines, line)
			} else {
				b := stack[len(stack)-1]
				b.Members = append(b.Members, line)
			}
		}
	}
	for _, b := range stack {
		d.Diagnostics = append(d.Diagnostics, fm.Diagnostic{Code: "unclosed-block", Span: b.Header.Span, Message: "native block is not closed"})
	}
	return d, nil
}
func (s Statement) Lines() []int {
	if s.Claims != nil {
		return append([]int{}, s.Claims...)
	}
	out := make([]int, 0, s.Span.Last-s.Span.First+1)
	for i := s.Span.First; i <= s.Span.Last; i++ {
		out = append(out, i)
	}
	return out
}
