// Package report turns an evaluation into the answer an operator asks
// for: which firewalls the traffic crosses, what NAT applies, and for each
// firewall whether access control fully permits it, partly permits it,
// blocks it, cannot decide it or needs a new rule; which existing rules are
// the best ones to modify and why the others are not; and the planned
// change. The report is structured data; the command line renders it.
package report
