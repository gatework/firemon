// Package design turns an access intent into a verified, vendor-neutral
// change plan.
//
// The Planner first queries the intent. Traffic that is already permitted
// needs nothing. Traffic decided by the default action or by a catch-all
// deny (any source to any destination) is the need the plan must open.
// Traffic denied by a specific deny rule is a conflict: it is reported and
// left alone unless the intent asks to override it.
//
// For each zone pair the need is opened by the cheapest of:
//
//   - extending one dimension (source, destination or service) of an
//     existing permit rule for exactly that zone pair, allowed only when
//     the rule's other two dimensions are contained in the intent, so the
//     extension cannot open anything outside it;
//   - adding a rule placed immediately before the first deny that decides
//     the need, or at the end of the rulebase.
//
// Objects are reused when an existing address or service object holds
// exactly the needed set; otherwise new objects are named by a Naming
// policy. Every plan is verified by applying it to a copy of the
// configuration, compiling and querying again: the need must become
// permitted, nothing outside the intent may become permitted, and
// conflicts must stay denied unless overridden.
package design
