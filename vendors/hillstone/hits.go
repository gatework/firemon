package hillstone

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gatework/firemon"
	"github.com/gatework/firemon/hits"
)

// HitCountCommand is the StoneOS command that lists the policy rules with
// their hit counters.
//
// Experimental: the command and its output format are taken from the
// StoneOS documentation and have not been checked against a device yet;
// pass another command to the collector when the device differs.
const HitCountCommand = "show policy"

// ErrNoHitCounters reports output without any rule counter.
var ErrNoHitCounters = errors.New("hillstone: no rule hit counters in the output")

var (
	hitRuleID = regexp.MustCompile(`(?i)\b(?:rule\s*id|policy\s*id|id)\s*[:=]?\s*(\d+)\b`)
	hitCount  = regexp.MustCompile(`(?i)\bhit[\s_-]*count(?:s)?\s*[:=]?\s*(\d+)\b`)
)

// ParseHits reads rule counters from output that names each rule by its id
// and its counter as "hit count N" (or "hit-count: N"), on one line or on a
// later line of the same rule's section. Lines with neither are ignored;
// a counter is only taken for the rule named before it, never guessed.
func ParseHits(text, firewall string, taken time.Time) (hits.Snapshot, error) {
	s := hits.Snapshot{Firewall: firewall, Vendor: firemon.VendorHillstone, Taken: taken}
	rule := ""
	seen := map[string]bool{}
	for line := range strings.Lines(text) {
		if m := hitRuleID.FindStringSubmatch(line); m != nil {
			rule = m[1]
		}
		m := hitCount.FindStringSubmatch(line)
		if m == nil || rule == "" || seen[rule] {
			continue
		}
		n, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			continue
		}
		seen[rule] = true
		s.Counters = append(s.Counters, hits.Counter{Rule: rule, Hits: n})
	}
	if len(s.Counters) == 0 {
		return hits.Snapshot{}, ErrNoHitCounters
	}
	return s, nil
}
