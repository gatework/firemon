package hillstone

import "strings"

// token is one word of a StoneOS line. Quoted strings keep their content
// without the quotes.
type token struct {
	text   string
	quoted bool
}

// tokenize splits a line on spaces, treating "..." as one token. An
// unterminated quote runs to the end of the line.
func tokenize(line string) []token {
	var out []token
	for i := 0; i < len(line); {
		switch line[i] {
		case ' ', '\t':
			i++
		case '"':
			end := strings.IndexByte(line[i+1:], '"')
			if end < 0 {
				out = append(out, token{text: line[i+1:], quoted: true})
				return out
			}
			out = append(out, token{text: line[i+1 : i+1+end], quoted: true})
			i += end + 2
		default:
			end := strings.IndexAny(line[i:], " \t")
			if end < 0 {
				end = len(line) - i
			}
			out = append(out, token{text: line[i : i+end]})
			i += end
		}
	}
	return out
}

// words is a cursor over the tokens of one line.
type words struct {
	toks []token
	pos  int
}

func newWords(line string) *words { return &words{toks: tokenize(line)} }

// next returns the next token text, or "" at the end.
func (w *words) next() string {
	if w.pos >= len(w.toks) {
		return ""
	}
	w.pos++
	return w.toks[w.pos-1].text
}

// peek returns the next token text without consuming it.
func (w *words) peek() string {
	if w.pos >= len(w.toks) {
		return ""
	}
	return w.toks[w.pos].text
}

// done reports whether every token was consumed.
func (w *words) done() bool { return w.pos >= len(w.toks) }

// rest returns the unconsumed tokens joined by spaces.
func (w *words) rest() string {
	parts := make([]string, 0, len(w.toks)-w.pos)
	for _, t := range w.toks[w.pos:] {
		parts = append(parts, t.text)
	}
	return strings.Join(parts, " ")
}
