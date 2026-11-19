package oracle_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/gatework/firemon"
)

// panApply replays PAN-OS set-format commands on a set-format
// configuration in order, as the device would: set adds a line, delete
// removes the lines under a path (or members of a list), and move
// reorders a rule's lines before another rule's.
func panApply(text string, cmds []string) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if text == "" {
		lines = nil
	}
	for _, c := range cmds {
		f := fields(c)
		switch {
		case len(f) > 1 && f[0] == "set":
			lines = append(lines, c)
		case len(f) > 1 && f[0] == "delete":
			lines = panDelete(lines, f[1:])
		case len(f) == 7 && f[0] == "move" && f[1] == "rulebase" && f[3] == "rules" && f[5] == "before":
			lines = panMove(lines, "set rulebase "+f[2]+" rules "+f[4]+" ", "set rulebase "+f[2]+" rules "+f[6]+" ")
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// panDelete removes the lines under path; a trailing bracketed list
// removes only those members from the lines that set that path.
func panDelete(lines, path []string) []string {
	var members []string
	if i := slices.Index(path, "["); i >= 0 {
		members = slices.DeleteFunc(slices.Clone(path[i+1:]), func(s string) bool { return s == "]" })
		path = path[:i]
	}
	prefix := "set " + strings.Join(path, " ")
	var out []string
	for _, l := range lines {
		if l != prefix && !strings.HasPrefix(l, prefix+" ") {
			out = append(out, l)
			continue
		}
		if members == nil {
			continue // the whole subtree goes
		}
		rest := slices.DeleteFunc(fields(strings.TrimPrefix(l, prefix)), func(s string) bool {
			return s == "[" || s == "]" || slices.Contains(members, s)
		})
		if len(rest) > 0 {
			out = append(out, prefix+" [ "+strings.Join(rest, " ")+" ]")
		}
	}
	return out
}

// panMove moves the lines of one rule before the first line of another.
func panMove(lines []string, move, before string) []string {
	var moved, rest []string
	for _, l := range lines {
		if strings.HasPrefix(l, move) {
			moved = append(moved, l)
		} else {
			rest = append(rest, l)
		}
	}
	i := slices.IndexFunc(rest, func(l string) bool { return strings.HasPrefix(l, before) })
	if i < 0 || len(moved) == 0 {
		return lines
	}
	return slices.Concat(rest[:i], moved, rest[i:])
}

// fields splits a command into words, keeping double-quoted words whole
// with their quotes.
func fields(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case r == ' ' && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func TestPanApply(t *testing.T) {
	t.Parallel()
	text := `set address a ip-netmask 10.0.0.1
set rulebase security rules r1 source [ a b c ]
set rulebase security rules r1 action allow
set rulebase security rules r2 action deny
`
	got := panApply(text, []string{
		"delete rulebase security rules r1 source [ b ]",
		"move rulebase security rules r2 before r1",
		"delete address a",
		"set address a ip-netmask 10.0.0.2",
	})
	want := `set rulebase security rules r2 action deny
set rulebase security rules r1 source [ a c ]
set rulebase security rules r1 action allow
set address a ip-netmask 10.0.0.2
`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

// sameObjects reports whether two configurations are equal up to the
// order of their named objects, which devices do not keep meaningful:
// a rollback recreates deleted objects at the end of their lists.
func sameObjects(a, b *firemon.Config) (bool, error) {
	fa, err := firemon.Compile(canonical(a))
	if err != nil {
		return false, err
	}
	fb, err := firemon.Compile(canonical(b))
	if err != nil {
		return false, err
	}
	return fa.Fingerprint() == fb.Fingerprint(), nil
}

func canonical(c *firemon.Config) *firemon.Config {
	out := *c
	byName := func(a, b string) int { return strings.Compare(a, b) }
	out.Addresses = slices.SortedStableFunc(slices.Values(c.Addresses), func(x, y firemon.Address) int { return byName(x.Name, y.Name) })
	out.AddressGroups = slices.SortedStableFunc(slices.Values(c.AddressGroups), func(x, y firemon.AddressGroup) int { return byName(x.Name, y.Name) })
	out.Services = slices.SortedStableFunc(slices.Values(c.Services), func(x, y firemon.Service) int { return byName(x.Name, y.Name) })
	out.ServiceGroups = slices.SortedStableFunc(slices.Values(c.ServiceGroups), func(x, y firemon.ServiceGroup) int { return byName(x.Name, y.Name) })
	out.Schedules = slices.SortedStableFunc(slices.Values(c.Schedules), func(x, y firemon.Schedule) int { return byName(x.Name, y.Name) })
	return &out
}
