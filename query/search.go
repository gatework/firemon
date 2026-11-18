package query

// search is the state of one query's path discovery. Every target,
// address family, NAT split and policy-route split draws on one budget, so
// a query never returns more than MaxPaths paths or splits a part into
// more than MaxSpaces pieces, and reports when it stopped early (ALG-2).
type search struct {
	*Engine
	paths      int
	incomplete bool
}

// admit counts one more path, or reports that the budget is spent.
func (e *search) admit() bool {
	if e.paths >= e.maxPaths {
		e.incomplete = true
		return false
	}
	e.paths++
	return true
}

// tooMany reports, and records, a split into more pieces than allowed.
func (e *search) tooMany(pieces int) bool {
	if pieces > e.max {
		e.incomplete = true
		return true
	}
	return false
}
