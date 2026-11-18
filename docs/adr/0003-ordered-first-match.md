# 0003 — Ordered first-match evaluation and differences from Perl

Status: accepted (2026-11-17)

## Decision

Policy queries evaluate rules in device order and the first rule matching a packet decides it, including deny rules. Disabled rules, expired windows and inactive schedules do not match. Traffic no rule matches takes the vendor default (`firemon.Semantics`).

## Intended differences from the Perl Searcher

| Perl behaviour | v2 behaviour | Reason |
|---|---|---|
| Considers only permit rules; ignores order and deny | First match in order, deny included | A permit shadowed by an earlier deny does not allow traffic. |
| `compare` returns `other` for both overlap and disjoint | `traffic.Relation` separates `overlap` and `disjoint` | Design must tell "partly covered" from "unrelated". |
| Zones from protected/unprotected zone ownership tables | Zones from longest-prefix routing in the device virtual router, overridable per request | Single-firewall scope; no external database. |
| Unparseable objects are skipped silently | Undecidable rules report `Indeterminate` | Never widen what cannot be evaluated. |
| `modify` extends a rule when two of three dimensions are equal | A rule is extended in one dimension only when the other two are contained in the intent | Extension must not permit traffic outside the intent. |
| Hillstone NAT parsing bugs (missing `$`, `realIpRange` assignment, empty zones) | Parsed per StoneOS syntax | Bugs, not semantics. |
