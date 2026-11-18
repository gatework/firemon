// Package migrate translates a firewall configuration of one vendor into
// the configuration of another: network, objects, schedules, rules in
// order and NAT, with a report that gives every item its fidelity.
//
// The translation never widens what the source permits and never changes
// it silently: what the target cannot express exactly is rewritten into an
// equivalent form when one exists (exclusions become explicit ranges,
// negation a complement object, rule-type a set of zone pairs), marked
// approximate with the reason when the difference is bounded and stated,
// and otherwise carried over disabled and marked untranslatable. The
// result is verified rule by rule against the source.
package migrate
