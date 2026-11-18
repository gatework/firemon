# 0002 — netipx for addresses, gatework/set for ports

Status: accepted (2026-11-17)

## Context

Matching needs exact union, intersection and difference over IPv4 and IPv6 addresses and over 16-bit port ranges. The standard library has `net/netip` values but no address sets. `gatework/set` stores integer ranges but has no 128-bit key and no difference. The Hillstone corpus contains IPv6 objects and routes.

## Decision

- Addresses: `go4.org/netipx` `IPSet`, the widely used, `net/netip`-native set implementation (GEN-4 justification: the standard library has no address set).
- Ports and protocols: `gatework/set` `Set[uint16]`; `traffic` implements difference by complement.
- Services are canonical piecewise maps protocol → source-port band → destination-port set, so equality is structural.
- Rule match spaces are products (`traffic.Space`); remaining traffic during evaluation is a union of disjoint products (`traffic.Region`), each subtraction producing at most three pieces.

## Consequences

`traffic` is the only package that imports either library. A fuzz test checks `Region` against an exhaustive point model.
