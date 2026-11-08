// Package config implements stateful, evidence-preserving configuration parsing.
package config

import (
	"context"
	"errors"
	"fmt"
	"slices"

	fm "github.com/gatework/firemon"
	"github.com/gatework/parser"
)

var ErrInvalid = errors.New("config: invalid input")
var ErrSource = errors.New("invalid configuration source")
var ErrClaim = errors.New("invalid source claim")
var ErrClosed = errors.New("transaction already closed")

type Source struct {
	Text     string
	Complete bool
	// ScheduleClock must come from an independently verified capture observation.
	ScheduleClock *fm.ScheduleClock
}

// DefaultMaxBytes bounds native configuration source size.
const DefaultMaxBytes = 16 << 20

// DefaultMaxServiceTerms bounds the accepted service catalog, not parse work.
const DefaultMaxServiceTerms = 100000

type Limits struct {
	MaxBytes, MaxLines, MaxDepth int
	// MaxServiceTerms bounds the total terms in the accepted service catalog
	// and in each pending transaction. Replacement and rollback release capacity.
	MaxServiceTerms int
}

func (l Limits) defaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxBytes
	}
	if l.MaxLines <= 0 {
		l.MaxLines = 200000
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = 64
	}
	if l.MaxServiceTerms <= 0 {
		l.MaxServiceTerms = DefaultMaxServiceTerms
	}
	return l
}

// Content combines an immutable physical source with semantic evidence. Evidence
// claims refer to physical lines for CLI input and byte fragments for XML input.
type Content struct {
	source   Source
	text     *parser.Content
	evidence []fm.Evidence
	owner    *Builder
	limits   Limits
}

// NewContent indexes physical lines without consuming semantic evidence.
func NewContent(ctx context.Context, source Source, limits Limits) (*Content, error) {
	c, err := newContent(ctx, source, limits)
	if err != nil {
		return nil, err
	}
	if c.text.Len() > 0 {
		c.evidence = make([]fm.Evidence, c.text.Len())
	}
	for line := range c.text.All() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.evidence[line.Number-1] = fm.Evidence{
			Span: fm.Span{First: line.Number, Last: line.Number}, State: fm.Pending,
		}
	}
	return c, nil
}

func newContent(ctx context.Context, source Source, limits Limits) (*Content, error) {
	limits = limits.defaults()
	if err := validateSource(ctx, source, limits); err != nil {
		return nil, err
	}
	text, err := parser.NewWithContext(ctx, source.Text, parser.Limits{
		MaxBytes: limits.MaxBytes, MaxLines: limits.MaxLines,
	})
	if err != nil {
		if errors.Is(err, parser.ErrLimit) {
			return nil, fmt.Errorf("%w: %w", ErrSource, err)
		}
		return nil, err
	}
	return &Content{source: source, text: text, limits: limits}, nil
}

// span locates a nonempty byte interval, including any terminating line ending.
func (c *Content) span(start, end int) (fm.Span, bool) {
	if start < 0 || end <= start || end > len(c.source.Text) {
		return fm.Span{}, false
	}
	first, _ := c.text.LineAt(start)
	last, _ := c.text.LineAt(end - 1)
	return fm.Span{First: first.Number, Last: last.Number, StartByte: start, EndByte: end}, true
}

// Lines returns physical lines with original indentation and line endings. It
// does not change evidence; XML claims may cover only part of a returned line.
func (c *Content) Lines() []parser.Line { return c.text.Lines() }

func (c *Content) Evidence() []fm.Evidence { return slices.Clone(c.evidence) }

// Limits returns the normalized limits shared by scanning and native parsing.
func (c *Content) Limits() Limits { return c.limits }
