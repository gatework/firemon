// Package hits holds rule hit counters read from devices: evidence of
// whether a rule is used. Counters say how often a rule matched since they
// were last reset, never which traffic matched, so they can show a rule
// unused over a window but cannot tell how to narrow it.
package hits
