package design

import (
	"cmp"

	"github.com/gatework/firemon/traffic"
)

// CandidateSearch records the cost order and verification trials for one
// exact region on a zone pair. Candidates contains at most the trial limit.
type CandidateSearch struct {
	From       string           `json:"from"`
	To         string           `json:"to"`
	Traffic    string           `json:"traffic"`
	Total      int              `json:"total"`
	Exhausted  bool             `json:"exhausted,omitempty"`
	Candidates []CandidateTrial `json:"candidates"`
}

// CandidateTrial describes an existing rule extension at the point it was
// priced. Selected means that this particular extension passed verification.
type CandidateTrial struct {
	Rule     string           `json:"rule"`
	Field    Field            `json:"field"`
	Cost     int              `json:"cost"`
	Src      traffic.Relation `json:"src"`
	Dst      traffic.Relation `json:"dst"`
	Service  traffic.Relation `json:"service"`
	Selected bool             `json:"selected,omitempty"`
	Error    string           `json:"error,omitempty"`
}

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

// CompareCandidates prefers the fewest configuration edits. Ties go to a
// rule connecting the same endpoints, then a logging rule, then device order.
func CompareCandidates(a, b CandidateKey) int {
	return cmp.Or(cmp.Compare(a.Cost, b.Cost), compareTrueFirst(a.BothEnds, b.BothEnds),
		compareTrueFirst(a.Logs, b.Logs), cmp.Compare(a.Position, b.Position))
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
