// Package config implements stateful, evidence-preserving configuration parsing.
package config

import (
	"context"
	"errors"
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
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

type Line struct {
	Number    int
	Raw, Text string
}
type Content struct {
	source   Source
	lines    []Line
	evidence []fm.Evidence
	position int
	owner    *Builder
	valid    bool
	limits   Limits
}

// NewContent indexes physical lines without consuming semantic evidence.
func NewContent(ctx context.Context, source Source, limits Limits) (*Content, error) {
	limits = limits.defaults()
	if err := validateSource(ctx, source, limits); err != nil {
		return nil, err
	}
	c := &Content{source: source, limits: limits, valid: true}
	start, nextCheck := 0, scanChunk
	for i := 0; i < len(source.Text); i++ {
		if i >= nextCheck {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			nextCheck = i + scanChunk
		}
		if source.Text[i] != '\n' && source.Text[i] != '\r' {
			continue
		}
		end := i + 1
		if source.Text[i] == '\r' && end < len(source.Text) && source.Text[end] == '\n' {
			i++
			end++
		}
		c.addLine(source.Text[start:end])
		start = end
		if len(c.lines) > limits.MaxLines {
			return nil, ErrSource
		}
	}
	if start < len(source.Text) {
		c.addLine(source.Text[start:])
	}
	if len(c.lines) > limits.MaxLines {
		return nil, ErrSource
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

// NewFragmentContent tracks a native scanner's exact, contiguous byte partitions.
// Claim numbers are fragment indexes, while persisted evidence retains physical
// line/byte spans. Reading and structural scanning do not consume any fragment.
func NewFragmentContent(ctx context.Context, source Source, spans []fm.Span, limits Limits) (*Content, error) {
	limits = limits.defaults()
	if err := validateSource(ctx, source, limits); err != nil {
		return nil, err
	}
	if len(spans) > limits.MaxLines {
		return nil, ErrSource
	}
	c := &Content{source: source, limits: limits, valid: true}
	end, line := 0, 1
	for _, span := range spans {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if span.StartByte != end || span.EndByte <= end || span.EndByte > len(source.Text) || span.First != line {
			return nil, ErrSource
		}
		raw := source.Text[span.StartByte:span.EndByte]
		last := line
		for i := range len(raw) {
			if i%scanChunk == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if raw[i] == '\n' {
				line++
			} else if raw[i] == '\r' && (span.StartByte+i+1 == len(source.Text) || source.Text[span.StartByte+i+1] != '\n') {
				line++
			}
			if i < len(raw)-1 {
				last = line
			}
		}
		if span.Last != last {
			return nil, ErrSource
		}
		n := len(c.lines) + 1
		c.lines = append(c.lines, Line{Number: n, Raw: raw, Text: strings.TrimSpace(raw)})
		c.evidence = append(c.evidence, fm.Evidence{Span: span, State: fm.Pending})
		end = span.EndByte
	}
	if end != len(source.Text) {
		return nil, ErrSource
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *Content) addLine(raw string) {
	n := len(c.lines) + 1
	c.lines = append(c.lines, Line{Number: n, Raw: raw, Text: strings.TrimSpace(raw)})
	c.evidence = append(c.evidence, fm.Evidence{Span: fm.Span{First: n, Last: n}, State: fm.Pending})
}
func (c *Content) Lines() []Line           { return slices.Clone(c.lines) }
func (c *Content) Evidence() []fm.Evidence { return slices.Clone(c.evidence) }

// Limits returns the normalized limits shared by scanning and native parsing.
func (c *Content) Limits() Limits { return c.limits }

func (c *Content) Peek() (Line, bool) {
	if c.position >= len(c.lines) {
		return Line{}, false
	}
	return c.lines[c.position], true
}
func (c *Content) NextPending() (Line, bool) {
	for c.position < len(c.lines) {
		p := c.position
		c.position++
		if c.evidence[p].State == fm.Pending {
			return c.lines[p], true
		}
	}
	return Line{}, false
}
func (c *Content) Rewind() { c.position = 0 }

type Checkpoint struct {
	owner    *Content
	position int
}

func (c *Content) Checkpoint() Checkpoint { return Checkpoint{c, c.position} }

// Restore rewinds reading, never committed semantic evidence.
func (c *Content) Restore(p Checkpoint) error {
	if p.owner != c {
		return ErrClaim
	}
	c.position = p.position
	return nil
}
