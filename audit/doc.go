// Package audit reviews a compiled firewall for rulebase hygiene and risk.
//
// Shadowing analysis walks the rules in order. For each decidable, active
// rule it subtracts the match spaces of the earlier rules that certainly
// apply to every zone pair the rule applies to; whatever is left is what the
// rule can still decide. A rule with nothing left is shadowed: redundant when
// every earlier rule that covers it has the same action (safe to remove), a
// conflict when an earlier rule with the opposite action takes part of it
// (the rule's intent is not in effect). Earlier rules that are undecidable,
// scheduled or disabled never count as covering, so findings are certain.
//
// The audit also lists disabled and expired rules, undecidable rules,
// permit rules matching any source, destination and service, and address
// and service objects no rule, group or NAT rule references.
package audit
