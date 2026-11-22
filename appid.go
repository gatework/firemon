package firemon

import (
	"cmp"
	"slices"
	"strings"

	"github.com/gatework/firemon/traffic"
)

// AppGuess is the application a firewall identifies on part of a service
// when the traffic is the standard application of its ports: the premise
// an operator makes when asking by five-tuple (tcp/22 is SSH).
type AppGuess struct {
	// Service is the part of the requested service this guess covers.
	Service traffic.ServiceSet
	// Apps are the lowercase applications whose standard ports are exactly
	// the most specific ones holding Service (ssh and ssh-putty on tcp/22).
	// Empty means no application of the book uses these ports: the device
	// identifies the traffic as unknown, and rules restricted to
	// applications do not match it.
	Apps []string
}

// Unidentified reports a guess no application of the book claims.
func (g AppGuess) Unidentified() bool { return len(g.Apps) == 0 }

// appClass is a set of standard ports and the applications that use
// exactly those ports.
type appClass struct {
	ports  traffic.ServiceSet
	weight uint64
	apps   []string
}

// compileAppClasses groups the application book by port set, most
// specific (fewest ports) first, then by name, so identification is
// deterministic.
func compileAppClasses(book ServiceBook) []appClass {
	var out []appClass
	for _, name := range book.Names() {
		ports, _ := book.Lookup(name)
		if ports.IsEmpty() || ports.IsAny() {
			continue
		}
		i := slices.IndexFunc(out, func(c appClass) bool { return c.ports.Equal(ports) })
		if i >= 0 {
			out[i].apps = append(out[i].apps, strings.ToLower(name))
			continue
		}
		out = append(out, appClass{ports: ports, weight: serviceWeight(ports), apps: []string{strings.ToLower(name)}})
	}
	slices.SortStableFunc(out, func(a, b appClass) int {
		return cmp.Or(cmp.Compare(a.weight, b.weight), strings.Compare(a.apps[0], b.apps[0]))
	})
	return out
}

// serviceWeight measures how many destination ports a set holds; the
// smaller, the more specific the application.
func serviceWeight(s traffic.ServiceSet) uint64 {
	var w uint64
	for r := range s.All() {
		protocols := uint64(r.ProtocolHigh) - uint64(r.ProtocolLow) + 1
		w += protocols * (uint64(r.Dst.High) - uint64(r.Dst.Low) + 1)
	}
	return w
}

// IdentifyApplications splits s by the standard application of its ports.
// Each port goes to the applications with the fewest standard ports that
// hold it; ports no application claims form an unidentified guess. The
// guesses are disjoint and cover s.
func (fw *Firewall) IdentifyApplications(s traffic.ServiceSet) []AppGuess {
	var out []AppGuess
	rest := s
	for _, c := range fw.appClasses {
		if rest.IsEmpty() {
			break
		}
		part := rest.Intersect(c.ports)
		if part.IsEmpty() {
			continue
		}
		out = append(out, AppGuess{Service: part, Apps: slices.Clone(c.apps)})
		rest = rest.Subtract(c.ports)
	}
	if !rest.IsEmpty() {
		out = append(out, AppGuess{Service: rest})
	}
	return out
}

// ApplicationGroupMembers returns the applications a predefined group
// holds, recursively and lowercase; false when name is not a group.
func (fw *Firewall) ApplicationGroupMembers(name string) ([]string, bool) {
	members, ok := fw.appGroups[strings.ToLower(name)]
	return members, ok
}

// expandAppGroups resolves application groups into their members, keeping
// the group names; cycles stop at the first repetition.
func expandAppGroups(groups map[string][]string) map[string][]string {
	lower := make(map[string][]string, len(groups))
	for g, ms := range groups {
		for _, m := range ms {
			lower[strings.ToLower(g)] = append(lower[strings.ToLower(g)], strings.ToLower(m))
		}
	}
	out := make(map[string][]string, len(lower))
	for g := range lower {
		seen := map[string]bool{g: true}
		var walk func(string)
		var members []string
		walk = func(name string) {
			for _, m := range lower[name] {
				if seen[m] {
					continue
				}
				seen[m] = true
				members = append(members, m)
				walk(m)
			}
		}
		walk(g)
		slices.Sort(members)
		out[g] = members
	}
	return out
}

// MatchesAnyApplication reports whether the rule admits one of apps,
// through its own list or a group it names. A rule without applications
// admits every application; with apps empty (unidentified traffic) only
// such a rule matches.
func (r *Rule) MatchesAnyApplication(apps []string) bool {
	if len(r.apps) == 0 {
		return true
	}
	for _, a := range apps {
		if slices.Contains(r.appSet, strings.ToLower(a)) {
			return true
		}
	}
	return false
}

// KnowsApplication reports whether the application book or a predefined
// group names app.
func (fw *Firewall) KnowsApplication(app string) bool {
	if _, ok := fw.cfg.Applications.Lookup(app); ok {
		return true
	}
	_, ok := fw.appGroups[strings.ToLower(app)]
	return ok
}

// ApplicationDisplay returns how the configuration spells app: the
// spelling of the first rule naming it, else app in upper case, the way
// vendors list predefined applications.
func (fw *Firewall) ApplicationDisplay(app string) string {
	if d, ok := fw.appDisplay[strings.ToLower(app)]; ok {
		return d
	}
	return strings.ToUpper(app)
}
