package cli

import "strings"

// padRight fills s with spaces to width columns.
func padRight(s string, width int) string {
	if d := width - displayWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// columns writes rows as aligned columns, two spaces apart; the first row
// is the header, numbers align right.
func columns(p *printer, indent string, rows [][]string) {
	if len(rows) == 0 {
		return
	}
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) {
				widths[i] = max(widths[i], displayWidth(c))
			}
		}
	}
	for _, r := range rows {
		parts := make([]string, len(r))
		for i, c := range r {
			if i > 0 && isNumber(c) {
				parts[i] = strings.Repeat(" ", widths[i]-displayWidth(c)) + c
				continue
			}
			parts[i] = padRight(c, widths[i])
		}
		p.f("%s%s\n", indent, strings.TrimRight(strings.Join(parts, "  "), " "))
	}
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}
