package hillstone

import (
	"strings"

	"github.com/gatework/netops/parse"
)

// block is one top-level StoneOS block: its head line and body lines. A
// single-line statement is a block without body.
type block struct {
	head parse.Line
	body []parse.Line
	last int // line number of the closing exit, or of the head for statements
}

// keyword returns the first word of the head.
func (b *block) keyword() string {
	k, _, _ := strings.Cut(b.head.Text, " ")
	return k
}

// segment splits content into top-level blocks.
//
// Current StoneOS output indents block bodies: a head at column zero opens a
// block when the next line is indented or "exit", and the block runs to the
// next "exit" at column zero; lines at column zero inside it are
// continuations of wrapped strings. Older output does not indent bodies, so
// the heads of policy-relevant blocks always open a block, which then runs
// to the first "exit" that does not close a nested rule.
func segment(content *parse.Content) []block {
	lines := content.Lines()
	var out []block
	for i := 0; i < len(lines); i++ {
		head := lines[i]
		if isBlank(head.Text) || isIndented(head.Text) || head.Text == "exit" {
			continue
		}
		b := block{head: head, last: head.Number}
		next := i + 1
		switch {
		case next < len(lines) && (isIndented(lines[next].Text) || lines[next].Text == "exit"):
			i = b.collect(lines, next, func(l parse.Line) bool { return l.Text == "exit" })
		case next < len(lines) && opensBlock(head.Text):
			depth := 0
			i = b.collect(lines, next, func(l parse.Line) bool {
				t := strings.TrimSpace(l.Text)
				switch {
				case strings.HasPrefix(t, "rule ") && b.keyword() == "policy":
					depth++
				case t == "exit" && depth > 0:
					depth--
				case t == "exit":
					return true
				}
				return false
			})
		}
		out = append(out, b)
	}
	return out
}

// collect appends lines from start until end reports the closing line and
// returns the index of that line (or of the last line).
func (b *block) collect(lines []parse.Line, start int, end func(parse.Line) bool) int {
	j := start
	for ; j < len(lines) && !end(lines[j]); j++ {
		b.body = append(b.body, lines[j])
	}
	if j >= len(lines) {
		j = len(lines) - 1
	}
	b.last = lines[j].Number
	return j
}

// opensBlock reports whether a head always opens a block, even when its
// body is not indented.
func opensBlock(head string) bool {
	k, rest, _ := strings.Cut(head, " ")
	switch k {
	case "address", "service", "servgroup", "schedule", "zone", "interface", "rule", "policy":
		return true
	case "ip":
		return strings.HasPrefix(rest, "vrouter ")
	default:
		return false
	}
}

func isIndented(s string) bool { return strings.HasPrefix(s, " ") || strings.HasPrefix(s, "\t") }

func isBlank(s string) bool { return strings.TrimSpace(s) == "" }
