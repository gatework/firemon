# 0011 — NAT order and policy-based routing

Status: accepted (2026-11-18)

## Decision

- NAT rules are first-match in configuration order, like security rules: the earlier rule wins, later rules never see traffic an earlier rule translated, and disabled rules are skipped. StoneOS lists `snatrule` entries in priority order (IDs are labels, not priorities); PAN-OS has one NAT rulebase. Query results carry the deciding rule's position, the exact traffic it translated and the disabled rules skipped before it.
- Policy-based routing (StoneOS `pbr-policy` with `match id` entries, bound to zones or interfaces) is modelled as `firemon.PolicyRoute` and `PolicyBinding`. Traffic entering a bound zone or interface takes the egress of the first matching entry, before the routing table; the zone pair and the source NAT on the egress interface follow from it. Domain targets match entries by domain pattern.
- An entry that cannot be decided offline (user groups, unresolved domains against address entries) branches: one path takes the entry, conditioned on it matching, the other continues without it; both are evaluated and reported with their conditions instead of making the whole query indeterminate.

## Consequences

On a StoneOS site edge, a source in a PBR-redirected group is reported with the uplink chosen by PBR and the snatrule that applies there, for example "源 NAT 5（第 4 条）" after the disabled rules 8, 3 and 4.
