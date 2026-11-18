// Package intake turns what an operator types into a precise request.
//
// Operators paste addresses and services from tickets, spreadsheets and
// chat: separated by commas, semicolons, spaces, new lines or Chinese
// punctuation; written as hosts, prefixes with host bits, address and mask
// pairs, ranges ("10.1.1.1-9"), wildcards ("10.1.1.*") or domain names;
// services as bare ports, "tcp 80", "80/tcp", "tcp:80", well-known names or
// applications. Parse accepts all of these, deduplicates and merges them,
// and reports every correction or assumption as a Note so the report can
// show exactly how the input was understood. Items it cannot read are
// reported and skipped; the query proceeds with the rest.
package intake
