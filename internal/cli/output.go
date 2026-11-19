package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/query"
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

// decisionView is the JSON form of a query decision.
type decisionView struct {
	Rule     string        `json:"rule"`
	Outcome  query.Outcome `json:"outcome"`
	Space    string        `json:"space"`
	Possible []string      `json:"possible,omitempty"`
}

// pathView is the JSON form of a query path.
type pathView struct {
	From           string         `json:"from"`
	To             string         `json:"to"`
	Ingress        string         `json:"ingress,omitempty"`
	Egress         string         `json:"egress,omitempty"`
	Original       string         `json:"original"`
	Policy         string         `json:"policy"`
	DestinationNAT string         `json:"destination_nat,omitempty"`
	SourceNAT      []string       `json:"source_nat,omitempty"`
	Verdict        query.Verdict  `json:"verdict"`
	Incomplete     bool           `json:"incomplete,omitempty"`
	Decisions      []decisionView `json:"decisions"`
	path           query.Path
}

func viewPath(p query.Path) pathView {
	v := pathView{
		From: p.From, To: p.To, Ingress: p.Ingress, Egress: p.Egress,
		Original: p.Original.String(), Policy: p.Policy.String(), Verdict: p.Verdict, Incomplete: p.Incomplete, path: p,
	}
	if p.DestinationNAT != nil {
		v.DestinationNAT = natLabel(*p.DestinationNAT)
	}
	for _, h := range p.SourceNAT {
		v.SourceNAT = append(v.SourceNAT, natLabel(h))
	}
	for _, d := range p.Decisions {
		dv := decisionView{Rule: ruleLabel(d.Rule), Outcome: d.Outcome, Space: d.Space.String()}
		for _, r := range d.Possible {
			dv.Possible = append(dv.Possible, r.ID())
		}
		v.Decisions = append(v.Decisions, dv)
	}
	return v
}

func natLabel(h query.NATHit) string {
	switch {
	case h.Rule != nil:
		return h.Side.String() + " nat " + h.Rule.Spec().ID + " -> " + h.Translated.String()
	case h.Static != nil:
		return h.Side.String() + " static nat " + h.Static.Spec().ID + " -> " + h.Translated.String()
	default:
		return h.Translated.String()
	}
}

// defaultLabel shows the default action in Chinese in text output; JSON
// keeps "(default)".
func defaultLabel(label string) string {
	if label == "(default)" {
		return "默认动作"
	}
	return label
}

// natLines describes the translations of a path in Chinese.
func natLines(p query.Path) []string {
	var out []string
	line := func(h query.NATHit) string {
		kind := "源地址转换"
		if h.Side == firemon.NATKindDestination {
			kind = "目的地址转换"
		}
		switch {
		case h.Rule != nil:
			return kind + "：NAT 规则 " + h.Rule.Spec().ID + " → " + h.Translated.String()
		case h.Static != nil:
			return kind + "：静态 NAT " + h.Static.Spec().ID + " → " + h.Translated.String()
		default:
			return kind + " → " + h.Translated.String()
		}
	}
	if p.DestinationNAT != nil {
		out = append(out, line(*p.DestinationNAT))
	}
	for _, h := range p.SourceNAT {
		out = append(out, line(h))
	}
	return out
}
