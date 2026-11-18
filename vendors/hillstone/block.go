package hillstone

import (
	"strings"

	"github.com/gatework/parser"
)

// block is one top-level StoneOS block: its head line and body lines. A
// single-line statement is a block without body.
type block struct {
	head parser.Line
	body []parser.Line
	last int // line number of the closing exit, or of the head for statements
}

// keyword returns the first word of the head.
func (b block) keyword() string {
	k, _, _ := strings.Cut(b.head.Text, " ")
	return k
}

// segment splits content into top-level blocks. A head at column zero opens
// a block when the next line is indented, a continuation, or "exit"; the
// block runs to the next "exit" at column zero. Lines at column zero inside
// a block are continuations of wrapped strings and stay in the body.
func segment(content *parser.Content) []block {
	lines := content.Lines()
	var out []block
	for i := 0; i < len(lines); i++ {
		head := lines[i]
		if isBlank(head.Text) || isIndented(head.Text) || head.Text == "exit" {
			continue
		}
		b := block{head: head, last: head.Number}
		if i+1 < len(lines) && (isIndented(lines[i+1].Text) || lines[i+1].Text == "exit") {
			j := i + 1
			for ; j < len(lines) && lines[j].Text != "exit"; j++ {
				b.body = append(b.body, lines[j])
			}
			if j < len(lines) {
				b.last = lines[j].Number
			} else {
				b.last = lines[len(lines)-1].Number
			}
			i = j
		}
		out = append(out, b)
	}
	return out
}

func isIndented(s string) bool { return strings.HasPrefix(s, " ") || strings.HasPrefix(s, "\t") }

func isBlank(s string) bool { return strings.TrimSpace(s) == "" }
