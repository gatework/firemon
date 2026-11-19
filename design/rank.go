package design

import "cmp"

// CandidateKey is what ranks an existing rule as the one to modify for a
// request.
type CandidateKey struct {
	// BothEnds: the rule already holds the request's sources and
	// destinations, so it serves the same systems and only lacks the
	// service.
	BothEnds bool
	// Logs: the rule logs its sessions.
	Logs bool
	// Cost is how many entries the change adds.
	Cost int
	// Position is the rule's place in the rulebase.
	Position int
}

// CompareCandidates orders candidate rules best first: the rule that
// already connects the same ends, then one that logs, then the smallest
// change, then the earliest rule. The planner and the report rank with it
// so that the recommended rule is the one the plan modifies.
func CompareCandidates(a, b CandidateKey) int {
	return cmp.Or(compareTrueFirst(a.BothEnds, b.BothEnds), compareTrueFirst(a.Logs, b.Logs),
		cmp.Compare(a.Cost, b.Cost), cmp.Compare(a.Position, b.Position))
}

func compareTrueFirst(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	default:
		return 1
	}
}
