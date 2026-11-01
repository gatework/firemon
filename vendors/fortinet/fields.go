package fortinet

import (
	"slices"
	"strings"

	fm "github.com/gatework/firemon"
	"github.com/gatework/firemon/config"
)

func readFields(tx *config.Transaction, b *config.Block, o *fm.Object) *fields {
	f := &fields{block: b, tx: tx, object: o, values: make(map[string]config.Statement), used: make(map[string]bool)}
	o.Spans = append(o.Spans, fm.Span{First: b.Header.Span.First, Last: b.End.Span.Last})
	borders(tx, b)
	for _, r := range b.Members {
		w := r.Words
		if len(w) == 0 || strings.HasPrefix(w[0], "#") {
			continue
		}
		if len(w) < 3 || w[0] != "set" {
			o.Unsupported = append(o.Unsupported, "unsupported object command")
			continue
		}
		if _, exists := f.values[w[1]]; exists {
			o.Unsupported = append(o.Unsupported, "repeated setting "+w[1])
			continue
		}
		f.values[w[1]] = r
	}
	if len(b.Children) > 0 {
		o.Unsupported = append(o.Unsupported, "unsupported nested object block")
	}
	return f
}
func (f *fields) list(key string) []string {
	r, ok := f.values[key]
	if !ok {
		return nil
	}
	if !f.used[key] {
		f.tx.Parse(r.Lines()...)
		f.used[key] = true
	}
	return slices.Clone(r.Words[2:])
}
func (f *fields) one(key, def string) string {
	if _, ok := f.values[key]; !ok {
		return def
	}
	v := f.list(key)
	if len(v) != 1 {
		f.invalid(key)
		return def
	}
	return v[0]
}
func (f *fields) invalid(key string) {
	f.object.Unsupported = append(f.object.Unsupported, "unsupported "+key)
}
func (f *fields) choice(key, def string, allowed ...string) string {
	value := f.one(key, def)
	if !slices.Contains(allowed, value) {
		f.invalid(key)
	}
	return value
}
func (f *fields) ignore(keys ...string) {
	for _, key := range keys {
		if r, ok := f.values[key]; ok && !f.used[key] {
			f.tx.Ignore("administrative object metadata", r.Lines()...)
			f.used[key] = true
		}
	}
}
func (f *fields) finish() {
	for _, r := range f.block.Members {
		if len(r.Words) >= 3 && r.Words[0] == "set" && !f.used[r.Words[1]] {
			f.invalid(r.Words[1])
		}
	}
}
