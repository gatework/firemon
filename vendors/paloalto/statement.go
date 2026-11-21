package paloalto

import (
	"strings"

	"github.com/gatework/netops/parse"
)

// statement is one "set" command: its words and its first and last line.
// A list "[ a b ]" becomes one word holding the members.
type statement struct {
	words []word
	first int
	last  int
}

// word is a scalar or a bracketed list.
type word struct {
	text  string
	list  []string
	isSet bool // true for "[ ... ]" lists
}

// values returns the scalar as a one-element list, or the list members.
func (w word) values() []string {
	if w.isSet {
		return w.list
	}
	return []string{w.text}
}

// statements extracts the set commands of content. A quoted value may
// continue over following lines (certificates and descriptions); those
// lines belong to the statement. Other lines are returned as strays.
func statements(content *parse.Content) (out []statement, strays []parse.Line) {
	lines := content.Lines()
	for i := 0; i < len(lines); i++ {
		text := lines[i].Text
		if !strings.HasPrefix(text, "set ") {
			if strings.TrimSpace(text) != "" {
				strays = append(strays, lines[i])
			}
			continue
		}
		first := lines[i].Number
		for strings.Count(text, `"`)%2 == 1 && i+1 < len(lines) {
			i++
			text += "\n" + lines[i].Text
		}
		out = append(out, statement{words: splitWords(strings.TrimPrefix(text, "set ")), first: first, last: lines[i].Number})
	}
	return out, strays
}

// splitWords tokenizes a statement body: quoted strings keep spaces and
// lose their quotes, "[ a b ]" becomes one list word.
func splitWords(text string) []word {
	var out []word
	var list *word
	for _, tok := range tokens(text) {
		switch {
		case tok == "[" && list == nil:
			list = &word{isSet: true}
		case tok == "]" && list != nil:
			out = append(out, *list)
			list = nil
		case list != nil:
			list.list = append(list.list, tok)
		default:
			out = append(out, word{text: tok})
		}
	}
	if list != nil {
		out = append(out, *list)
	}
	return out
}

func tokens(text string) []string {
	var out []string
	for i := 0; i < len(text); {
		switch text[i] {
		case ' ', '\t', '\n', '\r':
			i++
		case '"':
			end := strings.IndexByte(text[i+1:], '"')
			if end < 0 {
				return append(out, text[i+1:])
			}
			out = append(out, text[i+1:i+1+end])
			i += end + 2
		default:
			end := strings.IndexAny(text[i:], " \t\n\r")
			if end < 0 {
				end = len(text) - i
			}
			out = append(out, text[i:i+end])
			i += end
		}
	}
	return out
}

// path is a read cursor over a statement's words.
type path struct {
	words []word
	pos   int
}

// next returns the next scalar word, or "" at the end.
func (p *path) next() string {
	if p.pos >= len(p.words) {
		return ""
	}
	p.pos++
	return p.words[p.pos-1].text
}

// value returns the remaining words flattened into one list.
func (p *path) value() []string {
	var out []string
	for _, w := range p.words[p.pos:] {
		out = append(out, w.values()...)
	}
	p.pos = len(p.words)
	return out
}

// scalar returns the remaining words joined by spaces.
func (p *path) scalar() string { return strings.Join(p.value(), " ") }

// done reports whether every word was consumed.
func (p *path) done() bool { return p.pos >= len(p.words) }
