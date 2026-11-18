package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

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

func (p *printer) table(header string, rows [][]string) {
	if p.err != nil || len(rows) == 0 {
		return
	}
	tw := tabwriter.NewWriter(p.w, 0, 4, 2, ' ', 0)
	_, p.err = fmt.Fprintln(tw, header)
	for _, r := range rows {
		if p.err == nil {
			_, p.err = fmt.Fprintln(tw, strings.Join(r, "\t"))
		}
	}
	if p.err == nil {
		p.err = tw.Flush()
	}
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
}

func viewPath(p query.Path) pathView {
	v := pathView{
		From: p.From, To: p.To, Ingress: p.Ingress, Egress: p.Egress,
		Original: p.Original.String(), Policy: p.Policy.String(), Verdict: p.Verdict, Incomplete: p.Incomplete,
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
