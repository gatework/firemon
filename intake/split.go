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
