package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gatework/firemon"
)

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// printer accumulates text output and reports the first write error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) f(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

// table writes rows under a tab-separated header, columns aligned by
// display width so that Chinese text lines up.
func (p *printer) table(header string, rows [][]string) {
	if p.err != nil || len(rows) == 0 {
		return
	}
	all := append([][]string{strings.Split(header, "\t")}, rows...)
	widths := map[int]int{}
	for _, r := range all {
		for i, c := range r {
			widths[i] = max(widths[i], displayWidth(c))
		}
	}
	for _, r := range all {
		var b strings.Builder
		for i, c := range r {
			b.WriteString(c)
			if i < len(r)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-displayWidth(c)+2))
			}
		}
		p.f("%s\n", strings.TrimRight(b.String(), " "))
	}
}

// displayWidth counts East Asian wide characters as two columns.
func displayWidth(s string) int {
	n := 0
	for _, r := range s {
		switch {
		case r >= 0x1100 && r <= 0x115f, r >= 0x2e80 && r <= 0xa4cf, r >= 0xac00 && r <= 0xd7a3,
			r >= 0xf900 && r <= 0xfaff, r >= 0xfe30 && r <= 0xfe4f, r >= 0xff00 && r <= 0xff60, r >= 0xffe0 && r <= 0xffe6:
			n += 2
		default:
			n++
		}
	}
	return n
}

func ruleLabel(r *firemon.Rule) string {
	if r == nil {
		return "(default)"
	}
	if name := r.Spec().Name; name != "" && name != r.ID() {
		return r.ID() + " " + name
	}
	return r.ID()
}
