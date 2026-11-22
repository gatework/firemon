package intake

import (
	"strings"
	"unicode"
)

// fields splits operator input on commas, semicolons, whitespace and their
// full-width and Chinese forms.
func fields(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case ',', ';', '，', '；', '、', '|':
			return true
		default:
			return unicode.IsSpace(r)
		}
	})
}

// halfWidth folds full-width ASCII forms and the Chinese full stop, colon,
// slash and dashes operators paste from documents into ASCII.
func halfWidth(text string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 0xFF01 && r <= 0xFF5E:
			return r - 0xFEE0
		case r == '\u3000':
			return ' '
		case r == '。':
			return '.'
		case r == '—', r == '–', r == '～':
			return '-'
		default:
			return r
		}
	}, text)
}
