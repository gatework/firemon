// Package traffic is the exact set algebra behind policy matching.
//
// A firewall rule matches a five-tuple space: source addresses, destination
// addresses and a service (protocol, source port, destination port, or ICMP
// type and code). The package models those dimensions as immutable sets:
//
//   - [AddressSet] holds IPv4 and IPv6 addresses (backed by netipx).
//   - [PortSet] holds 16-bit port numbers (backed by gatework/set).
//   - [ServiceSet] holds protocol, source-port and destination-port tuples.
//   - [Space] is the product of the three, the shape of one rule.
//   - [Region] is a union of disjoint spaces, the shape of what remains
//     unmatched while rules are evaluated in order.
//
// Every value is immutable after construction and safe for concurrent use.
// Zero values are empty sets. Operations never mutate their receivers.
package traffic
