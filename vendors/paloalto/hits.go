package paloalto

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/hits"
)

// HitCountCommand reads the security rule hit counters of vsys1.
const HitCountCommand = "show rule-hit-count vsys vsys-name vsys1 rule-base security rules all"

// ErrNoHitCounters reports output without any counter row.
var ErrNoHitCounters = errors.New("paloalto: no rule hit counters in the output")

// hitRow is one row of "show rule-hit-count": the rule name (which may hold
// spaces), the count, then the last hit, last reset, first hit, creation
// and modification timestamps, "-" when absent. Rows are matched by their
// shape, not by column positions, since long names shift the columns.
var hitRow = regexp.MustCompile(`^\s*(.+?)\s+(\d+)((?:\s+(?:-|[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})){1,5})\s*$`)

var stamp = regexp.MustCompile(`-|[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}`)

// ParseHits reads the output of HitCountCommand. Timestamps are in the
// device time zone loc.
func ParseHits(text, firewall string, taken time.Time, loc *time.Location) (hits.Snapshot, error) {
	s := hits.Snapshot{Firewall: firewall, Vendor: firemon.VendorPaloAlto, Taken: taken}
	for line := range strings.Lines(text) {
		m := hitRow.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
		if m == nil || strings.HasPrefix(strings.TrimSpace(m[1]), "Rule Name") {
			continue
		}
		n, err := strconv.ParseUint(m[2], 10, 64)
		if err != nil {
			continue
		}
		ts := stamp.FindAllString(m[3], -1)
		at := func(i int) time.Time {
			if i >= len(ts) || ts[i] == "-" {
				return time.Time{}
			}
			t, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", ts[i], loc)
			if err != nil {
				return time.Time{}
			}
			return t
		}
		c := hits.Counter{Rule: strings.TrimSpace(m[1]), Hits: n, LastHit: at(0), FirstHit: at(2)}
		c.Reset = at(1)
		if mod := at(4); mod.After(c.Reset) {
			c.Reset = mod
		}
		if created := at(3); created.After(c.Reset) {
			c.Reset = created
		}
		s.Counters = append(s.Counters, c)
	}
	if len(s.Counters) == 0 {
		return hits.Snapshot{}, ErrNoHitCounters
	}
	return s, nil
}
