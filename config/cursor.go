// Package config implements stateful, evidence-preserving configuration parsing.
package config

import (
	"errors"
	"fmt"
	fm "github.com/gatework/firemon"
	"slices"
	"strings"
	"unicode/utf8"
)

var ErrSource = errors.New("invalid configuration source")
var ErrClaim = errors.New("invalid source claim")
var ErrClosed = errors.New("transaction already closed")

type Source struct {
	Text     string
	Complete bool
}

// DefaultMaxBytes bounds native configuration source size.
const DefaultMaxBytes = 16 << 20

type Limits struct{ MaxBytes, MaxLines, MaxDepth int }

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
	return l
}

type Line struct {
	Number    int
	Raw, Text string
}
type evidenceUndo struct {
	index    int
	previous fm.Evidence
}

type Cursor struct {
	source   Source
	lines    []Line
	evidence []fm.Evidence
	position int
	undo     []evidenceUndo
	tracking bool
	limits   Limits
}

func NewCursor(source Source, limits Limits) (*Cursor, error) {
	limits = limits.defaults()
	if len(source.Text) > limits.MaxBytes || !utf8.ValidString(source.Text) {
		return nil, ErrSource
	}
	c := &Cursor{source: source, limits: limits}
	start := 0
	for i := 0; i < len(source.Text); i++ {
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
	return c, nil
}

// NewFragmentCursor tracks a native scanner's exact, contiguous byte partitions.
// Claim numbers are fragment indexes, while persisted evidence retains physical
// line/byte spans. Reading and structural scanning do not consume any fragment.
func NewFragmentCursor(source Source, spans []fm.Span, limits Limits) (*Cursor, error) {
	limits = limits.defaults()
	if len(source.Text) > limits.MaxBytes || !utf8.ValidString(source.Text) || len(spans) > limits.MaxLines {
		return nil, ErrSource
	}
	c := &Cursor{source: source, limits: limits}
	end, line := 0, 1
	for _, span := range spans {
		if span.StartByte != end || span.EndByte <= end || span.EndByte > len(source.Text) || span.First != line {
			return nil, ErrSource
		}
		raw := source.Text[span.StartByte:span.EndByte]
		last := line
		for i := range len(raw) {
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
	return c, nil
}
func (c *Cursor) addLine(raw string) {
	n := len(c.lines) + 1
	c.lines = append(c.lines, Line{Number: n, Raw: raw, Text: strings.TrimSpace(raw)})
	c.evidence = append(c.evidence, fm.Evidence{Span: fm.Span{First: n, Last: n}, State: fm.Pending})
}
func (c *Cursor) Lines() []Line           { return slices.Clone(c.lines) }
func (c *Cursor) Evidence() []fm.Evidence { return slices.Clone(c.evidence) }
func (c *Cursor) Peek() (Line, bool) {
	if c.position >= len(c.lines) {
		return Line{}, false
	}
	return c.lines[c.position], true
}
func (c *Cursor) NextPending() (Line, bool) {
	for c.position < len(c.lines) {
		p := c.position
		c.position++
		if c.evidence[p].State == fm.Pending {
			return c.lines[p], true
		}
	}
	return Line{}, false
}
func (c *Cursor) Rewind() { c.position = 0 }

type Checkpoint struct {
	owner    *Cursor
	position int
}

func (c *Cursor) Checkpoint() Checkpoint { return Checkpoint{c, c.position} }

// Restore rewinds reading, never committed semantic evidence.
func (c *Cursor) Restore(p Checkpoint) error {
	if p.owner != c {
		return ErrClaim
	}
	c.position = p.position
	return nil
}

type Transaction struct {
	cursor     *Cursor
	checkpoint Checkpoint
	claims     []fm.Evidence
	draft      fm.Data
	closed     bool
}

func (c *Cursor) Begin() *Transaction { return &Transaction{cursor: c, checkpoint: c.Checkpoint()} }
func (t *Transaction) Parse(lines ...int) {
	if t.closed {
		return
	}
	for _, n := range lines {
		t.claims = append(t.claims, fm.Evidence{Span: fm.Span{First: n, Last: n}, State: fm.Parsed})
	}
}
func (t *Transaction) Ignore(reason string, lines ...int) {
	if t.closed {
		return
	}
	for _, n := range lines {
		t.claims = append(t.claims, fm.Evidence{Span: fm.Span{First: n, Last: n}, State: fm.Ignored, Reason: reason})
	}
}
func (t *Transaction) Emit(d fm.Data) {
	if !t.closed {
		appendData(&t.draft, d.Clone())
	}
}
func (t *Transaction) Rollback() {
	if !t.closed {
		_ = t.cursor.Restore(t.checkpoint)
		t.closed = true
		t.draft = fm.Data{}
		t.claims = nil
	}
}
func (t *Transaction) Commit(dst *fm.Data) error {
	if t.closed {
		return ErrClosed
	}
	if dst == nil {
		t.Rollback()
		return ErrClaim
	}
	seen := make(map[int]bool)
	for _, e := range t.claims {
		n := e.Span.First
		if n < 1 || n > len(t.cursor.lines) || seen[n] || t.cursor.evidence[n-1].State != fm.Pending || e.State == fm.Ignored && strings.TrimSpace(e.Reason) == "" {
			t.Rollback()
			return fmt.Errorf("%w at line %d", ErrClaim, n)
		}
		seen[n] = true
	}
	// All failure points precede this synchronous ownership transfer.
	appendData(dst, t.draft)
	t.draft = fm.Data{}
	for _, e := range t.claims {
		index := e.Span.First - 1
		e.Span = t.cursor.evidence[index].Span
		if t.cursor.tracking {
			t.cursor.undo = append(t.cursor.undo, evidenceUndo{index, t.cursor.evidence[index]})
		}
		t.cursor.evidence[index] = e
	}
	t.closed = true
	t.claims = nil
	return nil
}
func appendData(dst *fm.Data, d fm.Data) {
	dst.Diagnostics = append(dst.Diagnostics, d.Diagnostics...)
	dst.Zones = append(dst.Zones, d.Zones...)
	dst.Interfaces = append(dst.Interfaces, d.Interfaces...)
	dst.Routes = append(dst.Routes, d.Routes...)
	dst.Addresses = append(dst.Addresses, d.Addresses...)
	dst.AddressGroups = append(dst.AddressGroups, d.AddressGroups...)
	dst.Services = append(dst.Services, d.Services...)
	dst.ServiceGroups = append(dst.ServiceGroups, d.ServiceGroups...)
	dst.Schedules = append(dst.Schedules, d.Schedules...)
	dst.Rules = append(dst.Rules, d.Rules...)
	dst.RuleBindings = append(dst.RuleBindings, d.RuleBindings...)
	dst.StaticNATs = append(dst.StaticNATs, d.StaticNATs...)
	dst.DynamicNATs = append(dst.DynamicNATs, d.DynamicNATs...)
	dst.NATPools = append(dst.NATPools, d.NATPools...)
}
