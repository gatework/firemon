package migrate

import (
	"strconv"
	"strings"
)

// namespace separates names that may repeat across kinds.
type namespace uint8

const (
	nsAddress namespace = iota
	nsService
	nsSchedule
	nsRule
	nsNAT
)

// namer gives source names unique, valid target names.
type namer struct {
	sanitize func(string) string
	max      int
	taken    map[namespace]map[string]bool
	mapped   map[namespace]map[string]string
}

func newNamer(t Target) *namer {
	s := t.Sanitize
	if s == nil {
		s = func(n string) string { return n }
	}
	return &namer{sanitize: s, max: t.Capabilities.MaxNameLength, taken: map[namespace]map[string]bool{}, mapped: map[namespace]map[string]string{}}
}

// reserve marks a target name taken, such as a predefined service.
func (n *namer) reserve(ns namespace, name string) {
	if n.taken[ns] == nil {
		n.taken[ns] = map[string]bool{}
	}
	n.taken[ns][name] = true
}

// name returns the target name of a source name, the same on every call.
func (n *namer) name(ns namespace, source string) string {
	if t, ok := n.mapped[ns][source]; ok {
		return t
	}
	t := n.fresh(ns, source)
	if n.mapped[ns] == nil {
		n.mapped[ns] = map[string]string{}
	}
	n.mapped[ns][source] = t
	return t
}

// lookup returns the target name of a source name already named.
func (n *namer) lookup(ns namespace, source string) (string, bool) {
	t, ok := n.mapped[ns][source]
	return t, ok
}

// fresh returns a new unique name derived from base.
func (n *namer) fresh(ns namespace, base string) string {
	base = strings.TrimSpace(n.sanitize(base))
	if base == "" {
		base = "obj"
	}
	if n.max > 0 && len(base) > n.max {
		base = truncate(base, n.max)
	}
	candidate := base
	for i := 2; n.taken[ns][candidate]; i++ {
		suffix := "_" + strconv.Itoa(i)
		candidate = base + suffix
		if n.max > 0 && len(candidate) > n.max {
			candidate = truncate(base, n.max-len(suffix)) + suffix
		}
	}
	n.reserve(ns, candidate)
	return candidate
}

// truncate cuts s to at most n bytes without splitting a character.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
