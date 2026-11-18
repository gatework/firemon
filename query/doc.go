// Package query answers "does this firewall allow this traffic?".
//
// An Engine evaluates a Request against one compiled firemon.Firewall:
//
//  1. Path discovery splits the request by routing: the ingress zone comes
//     from the route back to each source, the egress zone from the route
//     to each destination (following next-vr hops). Static and destination
//     NAT translate destinations before the egress lookup.
//  2. Each path is evaluated against the security rules in device order;
//     the first rule matching a packet decides it, deny rules included.
//     Disabled rules and rules outside their schedule do not match. Traffic
//     no rule matches takes the vendor default action.
//  3. Undecidable rules (domain names, applications, unknown objects) are
//     possible matches: the packets they might match are marked unknown
//     instead of being decided, so the verdict becomes Indeterminate
//     rather than wrong.
//
// Evaluation is exact set algebra over traffic.Region and is bounded by
// Options.MaxSpaces; when the bound is exceeded the result is marked
// Incomplete and the undecided remainder is reported as unknown.
package query
