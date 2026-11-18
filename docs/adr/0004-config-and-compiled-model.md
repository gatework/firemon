# 0004 — Declarative Config and compiled Firewall

Status: accepted (2026-11-17)

## Decision

Two layers with distinct purposes replace the v0.2 record/object duplication:

- `firemon.Config` is plain data (exported fields) in device vocabulary, references by name. Parsers produce it, golden tests marshal it, design changes edit a copy of it.
- `firemon.Firewall`, built by `firemon.Compile`, owns a private copy and exposes resolved sets, ordered compiled rules, NAT rules and routing tables through methods. It is immutable and safe for concurrent use.

Unresolvable references never fail compilation; they become `Issue`s and make rules undecidable.

## Consequences

Verifying a plan is "apply to a Config copy, compile, query again". There is no draft/rollback machinery in the domain.
