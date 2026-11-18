package traffic

import (
	"slices"
	"strings"
	"unicode"
)

// DomainSet is an immutable set of domain-name patterns, as next-generation
// firewalls match them: exact names ("api.example.com"), subdomain
// wildcards ("*.example.com", every name below example.com) and suffix
// wildcards ("*example.com", every name ending in example.com, the
// Hillstone form). Names are compared without case and trailing dot. The
// zero value is empty.
type DomainSet struct {
	patterns []string // normalized, sorted, unique
}

// NewDomainSet returns the set of the given patterns; blank ones are skipped.
func NewDomainSet(patterns ...string) DomainSet {
	var out []string
	for _, p := range patterns {
		if p = NormalizeDomain(p); p != "" {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return DomainSet{patterns: slices.Compact(out)}
}

// NormalizeDomain lowercases a name or pattern and strips surrounding
// spaces and trailing dots. It is idempotent.
func NormalizeDomain(name string) string {
	name = strings.TrimLeftFunc(strings.ToLower(name), unicode.IsSpace)
	return strings.TrimRightFunc(name, func(r rune) bool { return r == '.' || unicode.IsSpace(r) })
}

// IsEmpty reports whether the set holds no pattern.
func (d DomainSet) IsEmpty() bool { return len(d.patterns) == 0 }

// Patterns returns the normalized patterns in sorted order.
func (d DomainSet) Patterns() []string { return slices.Clone(d.patterns) }

// Union returns the patterns of d and o.
func (d DomainSet) Union(o DomainSet) DomainSet {
	return NewDomainSet(slices.Concat(d.patterns, o.patterns)...)
}

// Match reports whether name matches a pattern of d. A name that is itself
// a pattern ("*.example.com") matches when every name it stands for
// matches: an equal pattern or a broader wildcard.
func (d DomainSet) Match(name string) bool {
	name = NormalizeDomain(name)
	if name == "" {
		return false
	}
	return slices.ContainsFunc(d.patterns, func(p string) bool { return patternCovers(p, name) })
}

// String writes the patterns joined by commas, or "none".
func (d DomainSet) String() string {
	if d.IsEmpty() {
		return "none"
	}
	return strings.Join(d.patterns, ",")
}

// patternCovers reports whether pattern p covers name n, where n may itself
// be a wildcard pattern.
func patternCovers(p, n string) bool {
	if p == n {
		return true
	}
	rest, wild := strings.CutPrefix(p, "*")
	if !wild {
		return false
	}
	// "*.example.com" covers "a.example.com" and "*.a.example.com";
	// "*example.com" also covers "example.com" and "myexample.com".
	target := strings.TrimPrefix(n, "*")
	if strings.HasPrefix(rest, ".") {
		return strings.HasSuffix(target, rest) && len(target) > len(rest)
	}
	return strings.HasSuffix(target, rest)
}
