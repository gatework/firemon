package hits

import (
	"cmp"
	"slices"
	"time"

	"github.com/gatework/firemon"
)

// Counter is the hit counter of one rule.
type Counter struct {
	// Rule is the rule ID: the StoneOS rule id or the PAN-OS rule name.
	Rule string `json:"rule"`
	Hits uint64 `json:"hits"`
	// FirstHit and LastHit are zero when the device does not report them
	// or the rule never matched.
	FirstHit time.Time `json:"first_hit,omitzero"`
	LastHit  time.Time `json:"last_hit,omitzero"`
	// Reset is when the counter was last reset or the rule last changed,
	// whichever is later; zero when unknown.
	Reset time.Time `json:"reset,omitzero"`
}

// Snapshot is the counters of one firewall read at one instant.
type Snapshot struct {
	Firewall string         `json:"firewall"`
	Vendor   firemon.Vendor `json:"vendor,omitzero"`
	Taken    time.Time      `json:"taken"`
	// Since is when the device started counting (boot, last global reset);
	// zero when unknown. A rule's window starts at the later of Since and
	// its own Reset.
	Since    time.Time `json:"since,omitzero"`
	Counters []Counter `json:"counters"`
}

// Counter returns the counter of a rule.
func (s Snapshot) Counter(rule string) (Counter, bool) {
	i := slices.IndexFunc(s.Counters, func(c Counter) bool { return c.Rule == rule })
	if i < 0 {
		return Counter{}, false
	}
	return s.Counters[i], true
}

// Window returns how long the counter of a rule has been observing, as of
// the snapshot; zero when the start is unknown.
func (s Snapshot) Window(rule string) time.Duration {
	c, _ := s.Counter(rule)
	start := s.Since
	if c.Reset.After(start) {
		start = c.Reset
	}
	if start.IsZero() || !s.Taken.After(start) {
		return 0
	}
	return s.Taken.Sub(start)
}

// Verdict is what the counters say about one rule.
type Verdict uint8

// Verdicts.
const (
	VerdictUnset Verdict = iota
	// VerdictUnknown: no counter for the rule, or a window shorter than
	// asked or of unknown length.
	VerdictUnknown
	// VerdictUnused: no hit over a window at least as long as asked.
	VerdictUnused
	// VerdictUsed: at least one hit.
	VerdictUsed
)

// String returns the verdict name.
func (v Verdict) String() string {
	switch v {
	case VerdictUnset:
		return "unset"
	case VerdictUnknown:
		return "unknown"
	case VerdictUnused:
		return "unused"
	case VerdictUsed:
		return "used"
	default:
		return "invalid"
	}
}

// MarshalText implements encoding.TextMarshaler.
func (v Verdict) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// Judge tells whether a rule was used, requiring at least minWindow of
// observation before calling it unused.
func (s Snapshot) Judge(rule string, minWindow time.Duration) Verdict {
	c, ok := s.Counter(rule)
	switch {
	case !ok:
		return VerdictUnknown
	case c.Hits > 0:
		return VerdictUsed
	case s.Window(rule) >= minWindow:
		return VerdictUnused
	default:
		return VerdictUnknown
	}
}

// Merge combines the snapshots of HA members into one: hits add up, the
// latest last hit and the earliest first hit win, and the window is the
// one every member observed (the latest start). Counters only one member
// has are kept as they are.
func Merge(firewall string, snaps ...Snapshot) Snapshot {
	out := Snapshot{Firewall: firewall}
	by := map[string]*Counter{}
	var order []string
	for _, s := range snaps {
		out.Vendor = cmp.Or(out.Vendor, s.Vendor)
		if s.Taken.After(out.Taken) {
			out.Taken = s.Taken
		}
		if s.Since.After(out.Since) {
			out.Since = s.Since
		}
		for _, c := range s.Counters {
			m, ok := by[c.Rule]
			if !ok {
				cc := c
				by[c.Rule] = &cc
				order = append(order, c.Rule)
				continue
			}
			m.Hits += c.Hits
			m.LastHit = latest(m.LastHit, c.LastHit)
			m.Reset = latest(m.Reset, c.Reset)
			if !c.FirstHit.IsZero() && (m.FirstHit.IsZero() || c.FirstHit.Before(m.FirstHit)) {
				m.FirstHit = c.FirstHit
			}
		}
	}
	for _, r := range order {
		out.Counters = append(out.Counters, *by[r])
	}
	return out
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
