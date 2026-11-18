// Package converge reviews a firewall's policy for cleanup: objects nothing
// uses, rules that never take effect, permits wider than they look needed,
// and rules that duplicate or can merge with others. Every finding names
// its evidence (static analysis or hit counters) and its tier: Safe
// findings can be planned as changes that keep the effective policy, which
// Plan verifies; Review findings are advice for an operator.
package converge
